import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.sparc.vulnjava.sinks.TokenVerifier;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/**
 * S7 signature bypass -- a property harness: no crash exists, so the harness states the property
 * "TokenVerifier.verify accepts a token only if the reference ES256 check does" and reports a
 * finding when it fails. Tokens are built from structured parts (header text, payload text, and
 * either a real signature or fuzzer bytes) so mutations stay meaningful. -Dsink.safe=true runs the fix.
 */
public class SinkTokenFuzzer {
    private static final boolean SAFE = Boolean.getBoolean("sink.safe");
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static KeyPair keys;

    public static void fuzzerInitialize() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        keys = g.generateKeyPair();
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
        boolean realSignature = data.consumeBoolean();
        String header = data.consumeString(64);
        String payload = data.consumeString(128);
        String signedPart = B64.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "."
                + B64.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        byte[] sig;
        if (realSignature) {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(keys.getPrivate());
            s.update(signedPart.getBytes(StandardCharsets.US_ASCII));
            sig = s.sign();
        } else {
            sig = data.consumeRemainingAsBytes();
        }
        String token = signedPart + "." + B64.encodeToString(sig);

        boolean accepted = TokenVerifier.verify(token, keys.getPublic(), SAFE);
        if (accepted && !TokenVerifier.referenceVerify(token, keys.getPublic())) {
            throw new FuzzerSecurityIssueCritical("Signature bypass: token accepted without a valid signature\nheader: " + header);
        }
    }
}
