package com.example.issuer.util;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

/**
 * Utility class for JWT signature operations.
 * Provides common methods for x5c certificate extraction and signature verification.
 */
public final class JwtSignatureUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtSignatureUtils.class);

    private JwtSignatureUtils() {
        // Utility class
    }

    /**
     * Extracts the public key from the x5c certificate chain in the JWT header.
     *
     * @param signedJWT the signed JWT containing x5c header
     * @return the extracted JWK, or null if no x5c is present or extraction fails
     */
    public static JWK extractKeyFromX5c(SignedJWT signedJWT) {
        try {
            List<Base64> x5cChain = signedJWT.getHeader().getX509CertChain();
            if (x5cChain == null || x5cChain.isEmpty()) {
                return null;
            }

            // Parse leaf certificate (first in chain)
            byte[] certBytes = x5cChain.get(0).decode();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(certBytes));

            // Extract public key and build JWK
            if (certificate.getPublicKey() instanceof ECPublicKey ecPublicKey) {
                return new ECKey.Builder(Curve.P_256, ecPublicKey).build();
            } else if (certificate.getPublicKey() instanceof RSAPublicKey rsaPublicKey) {
                return new RSAKey.Builder(rsaPublicKey).build();
            }

            logger.warn("⚠️Unsupported key type in x5c certificate: {}", certificate.getPublicKey().getAlgorithm());
            return null;

        } catch (Exception e) {
            logger.error("❌Failed to extract key from x5c", e);
            return null;
        }
    }

    /**
     * Verifies the signature of a signed JWT using the provided JWK.
     * Supports both RSA and EC key types.
     *
     * @param signedJWT the signed JWT to verify
     * @param jwk the public key to verify against
     * @return true if signature is valid, false otherwise
     */
    public static boolean verifySignature(SignedJWT signedJWT, JWK jwk) {
        try {
            JWSVerifier verifier;
            if (jwk.getKeyType() == KeyType.RSA) {
                RSAPublicKey publicKey = ((RSAKey) jwk).toRSAPublicKey();
                verifier = new RSASSAVerifier(publicKey);
            } else if (jwk.getKeyType() == KeyType.EC) {
                ECPublicKey publicKey = ((ECKey) jwk).toECPublicKey();
                verifier = new ECDSAVerifier(publicKey);
            } else {
                logger.warn("⚠️Unsupported key type for signature verification: {}", jwk.getKeyType());
                return false;
            }
            return signedJWT.verify(verifier);
        } catch (Exception e) {
            logger.error("❌Signature verification failed", e);
            return false;
        }
    }

    /**
     * Extracts key from x5c and verifies the JWT signature in one operation.
     *
     * @param signedJWT the signed JWT to verify
     * @return true if x5c is present and signature is valid, false otherwise
     */
    public static boolean verifySignatureWithX5c(SignedJWT signedJWT) {
        JWK key = extractKeyFromX5c(signedJWT);
        if (key == null) {
            logger.warn("⚠️No x5c certificate chain in JWT header");
            return false;
        }
        return verifySignature(signedJWT, key);
    }

}
