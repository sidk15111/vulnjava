package com.sparc.vulnjava.sinks;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/**
 * Sink S7: compact signed tokens (header.payload.signature, base64url), the shape of the JWTs MOSIP
 * services verify. Entry -> split -> decode header -> verify ES256 signature.
 *
 *   S7 signature bypass: a header with "alg":"none" is accepted without checking the signature
 *      (the classic JWT alg=none bug). No exception or crash -- only a property harness that
 *      compares against a reference verifier can see it.
 *
 * Passing safe=true rejects any algorithm other than ES256.
 */
public final class TokenVerifier {
    private TokenVerifier() {}

    /** Entry: true if the token is authentic under the given key. */
    public static boolean verify(String token, PublicKey key, boolean safe) {
        if (token == null) return false;
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) return false;
        String header;
        try {
            header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return false;
        }
        String alg = algorithm(header);
        if ("none".equals(alg)) {
            return !safe;                                                         // BUG (S7)
        }
        if (!"ES256".equals(alg)) return false;
        return checkSignature(parts[0] + "." + parts[1], parts[2], key);
    }

    /** Reference check the property harness compares against: ES256 only, always verifies. */
    public static boolean referenceVerify(String token, PublicKey key) {
        if (token == null) return false;
        String[] parts = token.split("\\.", -1);
        return parts.length == 3 && checkSignature(parts[0] + "." + parts[1], parts[2], key);
    }

    static String algorithm(String header) {
        int i = header.indexOf("\"alg\"");
        if (i < 0) return null;
        int colon = header.indexOf(':', i);
        int q1 = header.indexOf('"', colon + 1);
        int q2 = q1 < 0 ? -1 : header.indexOf('"', q1 + 1);
        return colon < 0 || q1 < 0 || q2 < 0 ? null : header.substring(q1 + 1, q2);
    }

    static boolean checkSignature(String signedPart, String sigB64, PublicKey key) {
        try {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initVerify(key);
            s.update(signedPart.getBytes(StandardCharsets.US_ASCII));
            return s.verify(Base64.getUrlDecoder().decode(sigB64));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }
}
