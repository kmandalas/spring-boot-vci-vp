package com.example.verifier.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.stereotype.Service;

import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Service for signing Authorization Requests as JWTs (JAR - JWT-Secured Authorization Request).
 * Uses X.509 certificate with x5c header for HAIP compliance.
 * Loads certificate and private key via Spring Boot SSL Bundles.
 */
@Service
public class JarSigningService {

    private final ECPrivateKey privateKey;
    private final X509Certificate certificate;
    private final String x509Hash;

    public JarSigningService(SslBundles sslBundles) throws Exception {
        SslBundle bundle = sslBundles.getBundle("verifier-signing");
        KeyStore keyStore = bundle.getStores().getKeyStore();

        // Get the first (and only) alias from the keystore
        String alias = keyStore.aliases().nextElement();

        // Extract private key and certificate
        this.privateKey = (ECPrivateKey) keyStore.getKey(alias, null);
        this.certificate = (X509Certificate) keyStore.getCertificate(alias);
        this.x509Hash = computeX509Hash();
    }

    private String computeX509Hash() throws Exception {
        // SHA-256 hash of DER-encoded certificate, base64url encoded
        byte[] derEncoded = certificate.getEncoded();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(derEncoded);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    /**
     * Returns the x509_hash client_id in format: x509_hash:<hash>
     */
    public String getClientId() {
        return "x509_hash:" + x509Hash;
    }

    /**
     * Returns just the hash portion for use in other contexts.
     */
    public String getX509Hash() {
        return x509Hash;
    }

    /**
     * Signs an authorization request as a JWT with x5c header.
     *
     * @param claims The authorization request claims (client_id, response_type, etc.)
     * @return Signed JWT string
     */
    public String signAuthorizationRequest(Map<String, Object> claims) throws JOSEException, CertificateEncodingException {
        // Build x5c header with certificate chain (just one cert for self-signed)
        Base64 certBase64 = Base64.encode(certificate.getEncoded());
        List<Base64> x5c = List.of(certBase64);

        // Build JWS header with x5c
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("oauth-authz-req+jwt"))
                .x509CertChain(x5c)
                .build();

        // Build claims set
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .issuer(getClientId())
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 300_000)); // 5 minutes

        // Add all provided claims
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            claimsBuilder.claim(entry.getKey(), entry.getValue());
        }

        JWTClaimsSet claimsSet = claimsBuilder.build();

        // Sign the JWT
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        ECDSASigner signer = new ECDSASigner(privateKey);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

}
