import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.sparc.vulnjava.sinks.DeviceRepository;
import java.sql.SQLException;

/** S5b SQL injection in prepareStatement text (SqlHooks meter). Boundary: DeviceRepository.countByZone. -Dsink.safe=true runs the fix. */
public class SinkSqlPreparedFuzzer {
    private static final boolean SAFE = Boolean.getBoolean("sink.safe");

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            DeviceRepository.countByZone(data.consumeRemainingAsString(), SAFE);
        } catch (IllegalArgumentException | SQLException e) {
            // bad length / database error: expected (injections are reported by the detector)
        }
    }
}
