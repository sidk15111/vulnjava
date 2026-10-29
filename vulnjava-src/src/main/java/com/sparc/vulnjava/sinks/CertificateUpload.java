package com.sparc.vulnjava.sinks;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;

/**
 * Sink S6: CA-certificate upload, modelled on keymanager's parseCertificateData (the calibration
 * keep 173b59f1d6). Entry -> non-blank check -> try PEM -> fall back to base64url P7B -> parse.
 *
 *   S6 uncaught parse error: the base64url decode sits outside the try block, so input that is
 *      neither PEM nor valid base64 throws IllegalArgumentException up to the caller (an HTTP 500
 *      in the real service). A robustness bug, impact 1 -- found by Jazzer's uncaught-exception check.
 *
 * Passing safe=true decodes inside the try.
 */
public final class CertificateUpload {
    private CertificateUpload() {}

    /** Entry: number of certificates in the uploaded data. */
    public static int uploadCaCertificate(String certificateData, boolean safe) {
        if (certificateData == null || certificateData.isBlank()) {
            throw new IllegalArgumentException("certificate data is empty");
        }
        try {
            return parse(certificateData.getBytes(StandardCharsets.UTF_8));   // PEM or DER as given
        } catch (CertificateException notPem) {
            // fall through: maybe base64url P7B data
        }
        byte[] p7b;
        if (safe) {
            try {
                p7b = Base64.getUrlDecoder().decode(certificateData);
            } catch (IllegalArgumentException e) {
                return 0;
            }
        } else {
            p7b = Base64.getUrlDecoder().decode(certificateData);                 // BUG (S6): outside try
        }
        try {
            return parse(p7b);
        } catch (CertificateException e) {
            return 0;
        }
    }

    static int parse(byte[] data) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return cf.generateCertificates(new ByteArrayInputStream(data)).size();
    }
}
