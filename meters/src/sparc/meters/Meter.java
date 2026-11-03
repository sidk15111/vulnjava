package sparc.meters;

import com.code_intelligence.jazzer.api.Jazzer;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Shared core of the sink meters (Phase 2).
 *
 * Every hook calls {@link #reached}: it tells the fuzzer a new state was hit (so inputs that
 * reach a sink, or reach it carrying the marker, are kept in the corpus) and, when an event
 * file is configured, logs it for the report generator.
 *
 * Configuration (system property, then environment variable):
 *   meter.events / METER_EVENTS   path of a JSONL event log; unset = no logging (e.g. on ClusterFuzz)
 *   meter.marker / METER_MARKER   marker token the dictionary injects (default FUZZMARK)
 *
 * The log keeps the first {@link #SAMPLES_PER_KEY} events per (sink, marker) with a stack trace,
 * and <events>.summary.json holds running counts, rewritten every few seconds and on every new key
 * (a crash may stop the JVM before shutdown hooks run).
 */
public final class Meter {
    public static final String MARKER = setting("meter.marker", "METER_MARKER", "FUZZMARK");
    private static final String EVENTS = setting("meter.events", "METER_EVENTS", null);
    private static final int SAMPLES_PER_KEY = 3;
    private static final int MAX_FRAMES = 14;

    private static final Map<String, AtomicLong> COUNTS = new ConcurrentHashMap<>();
    private static final Map<String, String> FIRST_ARG = new ConcurrentHashMap<>();
    private static Writer writer;
    /** Set while the meter does its own I/O, so the file hooks ignore it. */
    static final ThreadLocal<Boolean> BUSY = ThreadLocal.withInitial(() -> false);

    static {
        if (EVENTS != null) {
            BUSY.set(true);
            try {
                writer = new FileWriter(EVENTS, StandardCharsets.UTF_8, true);
            } catch (IOException e) {
                System.err.println("[meter] cannot open " + EVENTS + ": " + e);
            } finally {
                BUSY.set(false);
            }
            Thread t = new Thread(() -> {
                while (true) {
                    try { Thread.sleep(5000); } catch (InterruptedException e) { return; }
                    writeSummary();
                }
            }, "meter-summary");
            t.setDaemon(true);
            t.start();
        }
    }

    private Meter() {}

    static String setting(String prop, String env, String dflt) {
        String v = System.getProperty(prop);
        if (v == null) v = System.getenv(env);
        return v != null && !v.isEmpty() ? v : dflt;
    }

    /** A sink was reached. {@code arg} is the dangerous argument as text (may be null). */
    public static void reached(String sink, String arg, int hookId) {
        if (BUSY.get()) return;
        boolean marker = arg != null && arg.contains(MARKER);
        Jazzer.exploreState((byte) (marker ? 2 : 1), hookId);
        record("reached", sink, marker, arg);
    }

    /** A named condition worth reporting (e.g. an unhardened XML parser was built). */
    public static void signal(String name, String detail, int hookId) {
        if (BUSY.get()) return;
        Jazzer.exploreState((byte) 3, hookId);
        record("signal", name, false, detail);
    }

    private static void record(String type, String sink, boolean marker, String arg) {
        String key = type + ":" + sink + (marker ? "+marker" : "");
        long n = COUNTS.computeIfAbsent(key, k -> new AtomicLong()).incrementAndGet();
        if (writer == null || n > SAMPLES_PER_KEY) return;
        if (n == 1 && arg != null) FIRST_ARG.put(key, truncate(arg, 300));
        StringBuilder sb = new StringBuilder(512);
        sb.append("{\"t\":\"").append(type).append("\",\"sink\":\"").append(esc(sink))
          .append("\",\"marker\":").append(marker)
          .append(",\"n\":").append(n)
          .append(",\"arg\":").append(arg == null ? "null" : "\"" + esc(truncate(arg, 300)) + "\"")
          .append(",\"frames\":[");
        int added = 0;
        for (StackTraceElement f : Thread.currentThread().getStackTrace()) {
            String c = f.getClassName();
            if (c.startsWith("java.lang.Thread") || c.startsWith("sparc.meters.")
                    || c.startsWith("com.code_intelligence.jazzer.")) continue;
            if (added++ > 0) sb.append(',');
            sb.append('"').append(esc(c + "." + f.getMethodName() + ":" + f.getLineNumber())).append('"');
            if (added >= MAX_FRAMES) break;
        }
        sb.append("]}\n");
        BUSY.set(true);
        try {
            synchronized (Meter.class) {
                writer.write(sb.toString());
                writer.flush();
            }
        } catch (IOException ignored) {
        } finally {
            BUSY.set(false);
        }
        if (n == 1) writeSummary();
    }

    static void writeSummary() {
        if (EVENTS == null) return;
        StringBuilder sb = new StringBuilder("{\"counts\":{");
        int i = 0;
        for (Map.Entry<String, AtomicLong> e : COUNTS.entrySet()) {
            if (i++ > 0) sb.append(',');
            sb.append('"').append(esc(e.getKey())).append("\":").append(e.getValue().get());
        }
        sb.append("},\"first_arg\":{");
        i = 0;
        for (Map.Entry<String, String> e : FIRST_ARG.entrySet()) {
            if (i++ > 0) sb.append(',');
            sb.append('"').append(esc(e.getKey())).append("\":\"").append(esc(e.getValue())).append('"');
        }
        sb.append("},\"marker\":\"").append(esc(MARKER)).append("\"}\n");
        BUSY.set(true);
        try {
            Files.writeString(Paths.get(EVENTS + ".summary.json"), sb.toString(), StandardCharsets.UTF_8);
        } catch (IOException ignored) {
        } finally {
            BUSY.set(false);
        }
    }

    static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    static String esc(String s) {
        StringBuilder b = new StringBuilder(s.length() + 8);
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }
}
