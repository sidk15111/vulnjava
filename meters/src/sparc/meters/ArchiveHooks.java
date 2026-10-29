package sparc.meters;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;

import java.io.File;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.zip.ZipEntry;

/**
 * Archive sinks (zip slip, decompression bombs) and file-path traversal.
 *
 * Meters:   archive.entry  - a zip entry was read; arg = entry name (marker check)
 *           file.write / file.read - a file was opened; arg = path
 * Detects:  decompression bomb - one stream inflated more than meter.bomb_mb (default 16) MB
 *           path traversal     - a file opened at a path that really escapes via "../jazzer-traversal"
 *                                (the fuzzer is guided toward that canary). Harnesses that write under
 *                                a directory should declare it: System.setProperty("meter.base_dir", dir)
 */
public final class ArchiveHooks {
    private static final long BOMB_BYTES =
            Long.parseLong(Meter.setting("meter.bomb_mb", "METER_BOMB_MB", "16")) << 20;
    static final String TRAVERSAL_CANARY = "../jazzer-traversal";
    private static final Map<Object, long[]> INFLATED = Collections.synchronizedMap(new WeakHashMap<>());

    private ArchiveHooks() {}

    // ------------------------------------------------------------------ zip entries
    @MethodHook(type = HookType.AFTER, targetClassName = "java.util.zip.ZipInputStream", targetMethod = "getNextEntry")
    @MethodHook(type = HookType.AFTER, targetClassName = "java.util.zip.ZipFile", targetMethod = "getEntry")
    public static void entry(MethodHandle method, Object self, Object[] args, int hookId, Object ret) {
        if (ret instanceof ZipEntry) {
            String name = ((ZipEntry) ret).getName();
            Meter.reached("archive.entry", name, hookId);
            Jazzer.guideTowardsContainment(name, TRAVERSAL_CANARY, hookId);
        }
    }

    // ------------------------------------------------------------------ decompression bombs
    @MethodHook(type = HookType.AFTER, targetClassName = "java.util.zip.ZipInputStream", targetMethod = "read")
    @MethodHook(type = HookType.AFTER, targetClassName = "java.util.zip.InflaterInputStream", targetMethod = "read")
    @MethodHook(type = HookType.AFTER, targetClassName = "java.util.zip.GZIPInputStream", targetMethod = "read")
    public static void inflatedRead(MethodHandle method, Object self, Object[] args, int hookId, Object ret) {
        if (ret instanceof Integer) {
            int n = (Integer) ret;
            // read() returns one byte (0-255); read(byte[],int,int) returns a count
            add(self, args.length == 0 ? (n >= 0 ? 1 : 0) : Math.max(n, 0));
        }
    }

    @MethodHook(type = HookType.AFTER, targetClassName = "java.util.zip.ZipInputStream", targetMethod = "readAllBytes")
    @MethodHook(type = HookType.AFTER, targetClassName = "java.util.zip.ZipInputStream", targetMethod = "readNBytes")
    @MethodHook(type = HookType.AFTER, targetClassName = "java.util.zip.InflaterInputStream", targetMethod = "readAllBytes")
    @MethodHook(type = HookType.AFTER, targetClassName = "java.util.zip.GZIPInputStream", targetMethod = "readAllBytes")
    public static void inflatedBulk(MethodHandle method, Object self, Object[] args, int hookId, Object ret) {
        if (ret instanceof byte[]) add(self, ((byte[]) ret).length);
        else if (ret instanceof Integer) add(self, Math.max((Integer) ret, 0));
    }

    @MethodHook(type = HookType.AFTER, targetClassName = "java.util.zip.ZipInputStream", targetMethod = "transferTo")
    @MethodHook(type = HookType.AFTER, targetClassName = "java.util.zip.InflaterInputStream", targetMethod = "transferTo")
    public static void inflatedTransfer(MethodHandle method, Object self, Object[] args, int hookId, Object ret) {
        if (ret instanceof Long) add(self, (Long) ret);
    }

    private static void add(Object stream, long n) {
        long total;
        synchronized (INFLATED) {
            long[] c = INFLATED.computeIfAbsent(stream, k -> new long[1]);
            c[0] += n;
            total = c[0];
        }
        if (total > BOMB_BYTES) {
            INFLATED.remove(stream);
            Jazzer.reportFindingFromHook(new FuzzerSecurityIssueMedium(
                    "Decompression bomb: one archive stream inflated to " + (total >> 20)
                            + " MB with no size limit (threshold meter.bomb_mb=" + (BOMB_BYTES >> 20) + ")"));
        }
    }

    // ------------------------------------------------------------------ path traversal
    @MethodHook(type = HookType.BEFORE, targetClassName = "java.io.FileOutputStream", targetMethod = "<init>")
    @MethodHook(type = HookType.BEFORE, targetClassName = "java.io.FileWriter", targetMethod = "<init>")
    @MethodHook(type = HookType.BEFORE, targetClassName = "java.io.RandomAccessFile", targetMethod = "<init>")
    @MethodHook(type = HookType.BEFORE, targetClassName = "java.nio.file.Files", targetMethod = "newOutputStream")
    @MethodHook(type = HookType.BEFORE, targetClassName = "java.nio.file.Files", targetMethod = "write")
    @MethodHook(type = HookType.BEFORE, targetClassName = "java.nio.file.Files", targetMethod = "writeString")
    @MethodHook(type = HookType.BEFORE, targetClassName = "java.nio.file.Files", targetMethod = "copy")
    @MethodHook(type = HookType.BEFORE, targetClassName = "java.nio.file.Files", targetMethod = "createFile")
    @MethodHook(type = HookType.BEFORE, targetClassName = "java.nio.file.Files", targetMethod = "move")
    public static void fileWrite(MethodHandle method, Object self, Object[] args, int hookId) {
        checkPaths("file.write", args, hookId, true);
    }

    @MethodHook(type = HookType.BEFORE, targetClassName = "java.io.FileInputStream", targetMethod = "<init>")
    @MethodHook(type = HookType.BEFORE, targetClassName = "java.io.FileReader", targetMethod = "<init>")
    @MethodHook(type = HookType.BEFORE, targetClassName = "java.nio.file.Files", targetMethod = "newInputStream")
    @MethodHook(type = HookType.BEFORE, targetClassName = "java.nio.file.Files", targetMethod = "readAllBytes")
    @MethodHook(type = HookType.BEFORE, targetClassName = "java.nio.file.Files", targetMethod = "readString")
    public static void fileRead(MethodHandle method, Object self, Object[] args, int hookId) {
        checkPaths("file.read", args, hookId, false);
    }

    /**
     * True only for a real escape to the canary: the path has a ".." segment directly followed by the
     * "jazzer-traversal" segment (a directory named "FU.." doesn't count), and, when the harness declared
     * the directory the code must stay in (system property meter.base_dir), the normalised absolute path
     * lies outside it ("a/../jazzer-traversal" inside the directory doesn't count either).
     */
    static boolean escapes(String path) {
        String[] seg = path.split("/");
        boolean canary = false;
        for (int i = 1; i < seg.length; i++) {
            if (seg[i - 1].equals("..") && seg[i].equals("jazzer-traversal")) canary = true;
        }
        if (!canary) return false;
        String base = System.getProperty("meter.base_dir");
        if (base == null || base.isEmpty()) return true;
        try {
            Path abs = java.nio.file.Paths.get(path).toAbsolutePath().normalize();
            return !abs.startsWith(java.nio.file.Paths.get(base).toAbsolutePath().normalize());
        } catch (RuntimeException e) {
            return true;
        }
    }

    private static void checkPaths(String sink, Object[] args, int hookId, boolean write) {
        if (Meter.BUSY.get()) return;
        for (Object a : args) {
            String p = a instanceof File ? ((File) a).getPath()
                    : a instanceof Path ? a.toString()
                    : a instanceof String ? (String) a : null;
            if (p == null) continue;
            Meter.reached(sink, p, hookId);
            String norm = p.replace('\\', '/');
            Jazzer.guideTowardsContainment(norm, TRAVERSAL_CANARY, hookId);
            if (escapes(norm)) {
                Jazzer.reportFindingFromHook(new FuzzerSecurityIssueHigh(
                        "File path traversal: " + (write ? "write to " : "read of ") + p
                                + " (input-controlled path escaped its directory)"));
            }
        }
    }
}
