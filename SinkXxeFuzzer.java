import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.sparc.vulnjava.sinks.BiometricXml;
import java.io.IOException;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.SAXException;

/** S3 XXE. Boundary: BiometricXml.firstRecordText (CBEFF XML text). -Dsink.safe=true runs the fix. */
public class SinkXxeFuzzer {
    private static final boolean SAFE = Boolean.getBoolean("sink.safe");

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            BiometricXml.firstRecordText(data.consumeRemainingAsString(), SAFE);
        } catch (IllegalArgumentException | SAXException | IOException | ParserConfigurationException e) {
            // malformed XML, missing entity file, DOCTYPE rejected (fixed version): expected
        }
    }
}
