package dev.kmandalas.trustvalidator.util;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public final class X509Utils {

    private static final CertificateFactory CERT_FACTORY;

    static {
        try {
            CERT_FACTORY = CertificateFactory.getInstance("X.509");
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private X509Utils() {}

    /**
     * Decodes a Base64-encoded DER certificate (without PEM headers).
     */
    public static X509Certificate decodeBase64EncodedDer(String encoded) {
        var der = Base64.getDecoder().decode(encoded.strip());
        return decodeDer(der);
    }

    public static X509Certificate decodeDer(byte[] der) {
        try (var is = new java.io.ByteArrayInputStream(der)) {
            return (X509Certificate) CERT_FACTORY.generateCertificate(is);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to decode X.509 certificate: " + e.getMessage(), e);
        }
    }

    /**
     * Base64-encodes a certificate (no PEM headers, single line).
     */
    public static String base64Encode(X509Certificate cert) {
        try {
            return Base64.getEncoder().encodeToString(cert.getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encode certificate", e);
        }
    }
}
