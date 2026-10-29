import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.sparc.vulnjava.sinks.PacketArchive;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

/** S1 zip slip. Boundary: PacketArchive.storeDocuments (packet bytes as uploaded). -Dsink.safe=true runs the fix. */
public class SinkZipSlipFuzzer {
    private static final boolean SAFE = Boolean.getBoolean("sink.safe");
    private static File base;

    public static void fuzzerInitialize() throws IOException {
        base = Files.createTempDirectory("zipslip").resolve("packets").toFile();
        // tell the path-traversal meter which directory the code under test must stay inside
        System.setProperty("meter.base_dir", base.getAbsolutePath());
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        byte[] packet = data.consumeRemainingAsBytes();
        base.mkdirs();
        try {
            PacketArchive.storeDocuments(packet, base, SAFE);
        } catch (IllegalArgumentException | IOException e) {
            // not a packet / malformed zip / rejected entry: expected
        } finally {
            clean(base.toPath());
        }
    }

    private static void clean(Path dir) {
        try (Stream<Path> s = Files.walk(dir)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        } catch (IOException ignored) {
        }
    }
}
