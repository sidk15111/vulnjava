import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.sparc.vulnjava.sinks.EligibilityRules;
import java.util.HashMap;
import java.util.Map;

/** S4 MVEL injection. Boundary: EligibilityRules.hasField (field name from the request). -Dsink.safe=true runs the fix. */
public class SinkMvelFuzzer {
    private static final boolean SAFE = Boolean.getBoolean("sink.safe");
    private static final Map<String, Object> APPLICANT = new HashMap<>();

    static {
        APPLICANT.put("dateOfBirth", "1990/01/01");
        APPLICANT.put("gender", "F");
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            EligibilityRules.hasField(data.consumeRemainingAsString(), APPLICANT, SAFE);
        } catch (IllegalArgumentException e) {
            // rejected field name: expected
        } catch (RuntimeException e) {
            // MVEL compile/runtime errors on malformed expressions are expected; anything else is a finding
            if (!e.getClass().getName().startsWith("org.mvel2.")) throw e;
        }
    }
}
