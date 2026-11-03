import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.sparc.vulnjava.sinks.EligibilityRules;
import java.util.HashMap;
import java.util.Map;

/**
 * S4 MVEL injection. Boundary: EligibilityRules.hasField (field name from the request).
 * -Dsink.safe=true runs the fix.
 *
 * This harness tests one thing: whether injected expression text gets executed (Jazzer's honeypot
 * reports Remote Code Execution). Exceptions thrown from inside MVEL's own code on malformed
 * expressions are therefore set aside -- real MVEL throws plain JDK exceptions like
 * StringIndexOutOfBoundsException or even AssertionError from its parser, which would otherwise end
 * every run before the injection is found. Those parser crashes are real robustness bugs, just not this test's target:
 * run with -Dsink.mvel_crashes=true to have them reported. Jazzer findings always propagate.
 */
public class SinkMvelFuzzer {
    private static final boolean SAFE = Boolean.getBoolean("sink.safe");
    private static final boolean REPORT_MVEL_CRASHES = Boolean.getBoolean("sink.mvel_crashes");
    private static final Map<String, Object> APPLICANT = new HashMap<>();

    static {
        APPLICANT.put("dateOfBirth", "1990/01/01");
        APPLICANT.put("gender", "F");
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            EligibilityRules.hasField(data.consumeRemainingAsString(), APPLICANT, SAFE);
        } catch (Throwable t) {
            if (isJazzerFinding(t) || t instanceof OutOfMemoryError) throw sneaky(t);
            if (t.getClass().getName().startsWith("org.mvel2.")) return;          // MVEL compile/runtime error
            if (thrownInsideMvel(t)) {                                             // MVEL parser crash (see above)
                if (REPORT_MVEL_CRASHES) throw sneaky(t);
                return;
            }
            if (t instanceof IllegalArgumentException) return;                    // field name rejected by EligibilityRules
            throw sneaky(t);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T extends Throwable> RuntimeException sneaky(Throwable t) throws T {
        throw (T) t;   // rethrow any Throwable unchanged
    }

    private static boolean isJazzerFinding(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c.getClass().getName().startsWith("com.code_intelligence.jazzer.")) return true;
        }
        return false;
    }

    /** True if the first non-JDK frame (the code that triggered the exception) is MVEL's. */
    private static boolean thrownInsideMvel(Throwable t) {
        for (StackTraceElement f : t.getStackTrace()) {
            String c = f.getClassName();
            if (c.startsWith("java.") || c.startsWith("jdk.") || c.startsWith("sun.")) continue;
            return c.startsWith("org.mvel2.");
        }
        return false;
    }
}
