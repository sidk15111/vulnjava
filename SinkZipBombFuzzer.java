import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.sparc.vulnjava.sinks.PacketArchive;
import java.io.IOException;

/** S2 decompression bomb. Boundary: PacketArchive.readDocument. -Dsink.safe=true runs the fix. */
public class SinkZipBombFuzzer {
    private static final boolean SAFE = Boolean.getBoolean("sink.safe");

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            PacketArchive.readDocument(data.consumeRemainingAsBytes(), "id.json", SAFE);
        } catch (IllegalArgumentException | IOException e) {
            // expected for non-packets and oversized documents (fixed version)
        }
    }
}
