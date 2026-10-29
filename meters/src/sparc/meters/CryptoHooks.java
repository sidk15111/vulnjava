package sparc.meters;

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;

/**
 * Crypto and token sinks. These have no crash-style oracle: bugs here are logic bugs, so detection
 * lives in the harness as a property (e.g. "verify() accepts only what the reference verifier
 * accepts"). The meters only tell the loop whether the harness reaches the verification point.
 *
 * Meters:   crypto.signature.verify, crypto.cert.parse, jwt.decode, jwt.verify
 * Signals:  crypto.weak-mode - Cipher.getInstance with ECB or a bare algorithm name (defaults to ECB)
 */
public final class CryptoHooks {
    private CryptoHooks() {}

    @MethodHook(type = HookType.BEFORE, targetClassName = "java.security.Signature", targetMethod = "verify")
    public static void signature(MethodHandle method, Object self, Object[] args, int hookId) {
        Meter.reached("crypto.signature.verify", null, hookId);
    }

    @MethodHook(type = HookType.BEFORE, targetClassName = "java.security.cert.CertificateFactory", targetMethod = "generateCertificate")
    @MethodHook(type = HookType.BEFORE, targetClassName = "java.security.cert.CertificateFactory", targetMethod = "generateCertificates")
    @MethodHook(type = HookType.BEFORE, targetClassName = "java.security.cert.CertificateFactory", targetMethod = "generateCertPath")
    public static void certParse(MethodHandle method, Object self, Object[] args, int hookId) {
        Meter.reached("crypto.cert.parse", null, hookId);
    }

    @MethodHook(type = HookType.BEFORE, targetClassName = "com.auth0.jwt.JWT", targetMethod = "decode")
    @MethodHook(type = HookType.BEFORE, targetClassName = "com.nimbusds.jwt.SignedJWT", targetMethod = "parse")
    @MethodHook(type = HookType.BEFORE, targetClassName = "com.nimbusds.jose.JWSObject", targetMethod = "parse")
    @MethodHook(type = HookType.BEFORE, targetClassName = "io.jsonwebtoken.JwtParser", targetMethod = "parseClaimsJwt")
    public static void jwtDecode(MethodHandle method, Object self, Object[] args, int hookId) {
        Meter.reached("jwt.decode", args.length > 0 && args[0] instanceof String ? (String) args[0] : null, hookId);
    }

    @MethodHook(type = HookType.BEFORE, targetClassName = "com.auth0.jwt.interfaces.JWTVerifier", targetMethod = "verify")
    @MethodHook(type = HookType.BEFORE, targetClassName = "com.nimbusds.jose.JWSObject", targetMethod = "verify")
    @MethodHook(type = HookType.BEFORE, targetClassName = "io.jsonwebtoken.JwtParser", targetMethod = "parseClaimsJws")
    public static void jwtVerify(MethodHandle method, Object self, Object[] args, int hookId) {
        Meter.reached("jwt.verify", args.length > 0 && args[0] instanceof String ? (String) args[0] : null, hookId);
    }

    @MethodHook(type = HookType.BEFORE, targetClassName = "javax.crypto.Cipher", targetMethod = "getInstance")
    public static void cipher(MethodHandle method, Object self, Object[] args, int hookId) {
        if (args.length > 0 && args[0] instanceof String) {
            String t = (String) args[0];
            if (t.contains("/ECB/") || !t.contains("/") && (t.equals("AES") || t.equals("DES") || t.equals("DESede"))) {
                Meter.signal("crypto.weak-mode", t, hookId);
            }
        }
    }
}
