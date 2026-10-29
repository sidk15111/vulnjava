import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.sparc.vulnjava.sinks.CertificateUpload;

/**
 * S6 uncaught parse error. Boundary: CertificateUpload.uploadCaCertificate.
 * Respects the entry's only precondition (non-blank) and catches nothing else: any exception that
 * escapes is the finding. -Dsink.safe=true runs the fix.
 */
public class SinkCertFuzzer {
    private static final boolean SAFE = Boolean.getBoolean("sink.safe");

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String certificateData = data.consumeRemainingAsString();
        if (certificateData.isBlank()) return;
        CertificateUpload.uploadCaCertificate(certificateData, SAFE);
    }
}
