import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.sparc.vulnjava.sinks.DeviceRepository;
import java.sql.SQLException;

/** S5a SQL injection via Statement (Jazzer built-in detector). Boundary: DeviceRepository.countByName. -Dsink.safe=true runs the fix. */
public class SinkSqlStatementFuzzer {
    private static final boolean SAFE = Boolean.getBoolean("sink.safe");

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            DeviceRepository.countByName(data.consumeRemainingAsString(), SAFE);
        } catch (IllegalArgumentException | SQLException e) {
            // bad length / database error: expected (injections are reported by the detector)
        }
    }
}
