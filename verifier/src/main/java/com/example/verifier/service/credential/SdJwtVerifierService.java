package com.example.verifier.service.credential;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectDecoder;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Service for verifying SD-JWT Verifiable Presentations.
 * Handles signature verification, key binding validation, and claim extraction.
 */
@Service
public class SdJwtVerifierService {

    private static final Logger logger = LoggerFactory.getLogger(SdJwtVerifierService.class);

    private final ObjectMapper objectMapper;

    public SdJwtVerifierService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Result of SD-JWT verification containing status and disclosed claims.
     */
    public record SdJwtValidationResult(boolean valid, String issuer, Map<String, Object> disclosedClaims, String error) {
        public static SdJwtValidationResult success(String issuer, Map<String, Object> claims) {
            return new SdJwtValidationResult(true, issuer, claims, null);
        }

        public static SdJwtValidationResult failure(String error) {
            return new SdJwtValidationResult(false, null, Map.of(), error);
        }
    }

    /**
     * Verifies an SD-JWT VP token and extracts disclosed claims.
     *
     * @param vpToken   the SD-JWT VP token
     * @param issuerKey the issuer's public key for signature verification
     * @return SdJwtValidationResult with status and claims
     */
    public SdJwtValidationResult verifySdJwtPresentation(String vpToken, JWK issuerKey) {
        try {
            // Step 1: Parse the VP Token
            SDJWT vp = SDJWT.parse(vpToken);

            // Step 2: Parse credential JWT to extract issuer
            SignedJWT credentialJwt = SignedJWT.parse(vp.getCredentialJwt());
            String issuer = credentialJwt.getJWTClaimsSet().getIssuer();

            // Step 3: Extract and validate x5c key matches JWKS
            JWK x5cKey = extractKeyFromX5c(credentialJwt);
            if (x5cKey == null) {
                return SdJwtValidationResult.failure("Failed to extract key from x5c header");
            }
            if (!keysMatch(issuerKey, x5cKey)) {
                logger.warn("x5c key does not match JWKS key - possible tampering");
                return SdJwtValidationResult.failure("x5c key does not match issuer JWKS");
            }
            logger.debug("x5c key matches JWKS key - cross-check passed");

            // Step 4: Verify credential JWT signature
            verifyCredentialJwt(vp, issuerKey);
            logger.debug("Credential JWT signature verified");

            // Step 5: Verify binding JWT (key binding proof)
            verifyBindingJwt(vp);
            logger.debug("Binding JWT signature verified");

            // Step 6: Extract disclosed claims
            Map<String, Object> claims = extractDisclosedClaims(vpToken);

            return SdJwtValidationResult.success(issuer, claims);

        } catch (Exception e) {
            logger.error("SD-JWT VP validation failed", e);
            return SdJwtValidationResult.failure(e.getMessage());
        }
    }

    /**
     * Gets the JWTClaimsSet from the credential JWT for status checking.
     */
    public JWTClaimsSet getCredentialClaims(String vpToken) throws ParseException {
        SDJWT vp = SDJWT.parse(vpToken);
        SignedJWT credentialJwt = SignedJWT.parse(vp.getCredentialJwt());
        return credentialJwt.getJWTClaimsSet();
    }

    /**
     * Extracts the issuer from the credential JWT.
     */
    public String extractIssuer(String vpToken) throws ParseException {
        SDJWT vp = SDJWT.parse(vpToken);
        SignedJWT credentialJwt = SignedJWT.parse(vp.getCredentialJwt());
        return credentialJwt.getJWTClaimsSet().getIssuer();
    }

    /**
     * Extracts the issuer's public key from the x5c certificate chain in the JWT header.
     */
    public JWK extractKeyFromX5c(SignedJWT credentialJwt) {
        try {
            List<com.nimbusds.jose.util.Base64> x5cChain = credentialJwt.getHeader().getX509CertChain();
            if (x5cChain == null || x5cChain.isEmpty()) {
                logger.error("No x5c certificate chain in credential JWT header");
                return null;
            }

            // Parse leaf certificate (first in chain)
            byte[] certBytes = x5cChain.getFirst().decode();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(certBytes));

            // Extract EC public key and build JWK
            ECPublicKey ecPublicKey = (ECPublicKey) certificate.getPublicKey();
            logger.debug("Extracted issuer public key from x5c header");

            return new ECKey.Builder(Curve.P_256, ecPublicKey).build();

        } catch (Exception e) {
            logger.error("Failed to extract key from x5c", e);
            return null;
        }
    }

    /**
     * Compares two JWKs by their public key thumbprint.
     */
    public boolean keysMatch(JWK jwksKey, JWK x5cKey) {
        try {
            String jwksThumbprint = jwksKey.computeThumbprint().toString();
            String x5cThumbprint = x5cKey.computeThumbprint().toString();
            return jwksThumbprint.equals(x5cThumbprint);
        } catch (Exception e) {
            logger.error("Failed to compute key thumbprints", e);
            return false;
        }
    }

    // ========== Private verification methods ==========

    private void verifyCredentialJwt(SDJWT vp, JWK issuerKey) throws ParseException, JOSEException {
        SignedJWT credentialJwt = SignedJWT.parse(vp.getCredentialJwt());
        boolean verified = verifySignature(credentialJwt, issuerKey);
        Assert.isTrue(verified, "Credential JWT signature verification failed.");
    }

    private void verifyBindingJwt(SDJWT vp) throws ParseException, JOSEException {
        // Extract the binding key from the payload of the credential JWT
        JWK bindingKey = extractBindingKey(vp);

        // Parse the binding JWT
        SignedJWT bindingJwt = SignedJWT.parse(vp.getBindingJwt());

        // Verify the signature of the binding JWT
        boolean verified = verifySignature(bindingJwt, bindingKey);
        Assert.isTrue(verified, "Binding JWT signature verification failed.");

        // Extract the value of the "sd_hash" from the binding JWT
        String sdHash = bindingJwt.getJWTClaimsSet().getStringClaim("sd_hash");

        // The value of the "sd_hash" in the binding JWT must match
        // the actual SD hash value of the verifiable presentation
        Assert.isTrue(vp.getSDHash().equals(sdHash), "SD hash mismatch in binding JWT");
    }

    @SuppressWarnings("unchecked")
    private JWK extractBindingKey(SDJWT vp) throws ParseException {
        SignedJWT jwt = SignedJWT.parse(vp.getCredentialJwt());
        JWTClaimsSet claims = jwt.getJWTClaimsSet();
        Object cnf = claims.getClaim("cnf");
        Object jwk = ((Map<String, Object>) cnf).get("jwk");
        return JWK.parse((Map<String, Object>) jwk);
    }

    private boolean verifySignature(SignedJWT jwt, JWK verificationKey) throws JOSEException {
        JWSVerifier verifier = createVerifier(jwt, verificationKey);
        return jwt.verify(verifier);
    }

    private JWSVerifier createVerifier(SignedJWT jwt, JWK verificationKey) throws JOSEException {
        Key key = convertToPublicKey(verificationKey);
        return new DefaultJWSVerifierFactory().createJWSVerifier(jwt.getHeader(), key);
    }

    private PublicKey convertToPublicKey(JWK jwk) throws JOSEException {
        KeyType keyType = jwk.getKeyType();

        if (KeyType.EC.equals(keyType)) {
            return jwk.toECKey().toPublicKey();
        } else if (KeyType.RSA.equals(keyType)) {
            return jwk.toRSAKey().toPublicKey();
        } else if (KeyType.OKP.equals(keyType)) {
            return jwk.toOctetKeyPair().toPublicKey();
        } else {
            throw new JOSEException(String.format("The key type '%s' is not supported.", keyType));
        }
    }

    // ========== Claim extraction ==========

    /**
     * Extracts disclosed claims from an SD-JWT VP token using SDObjectDecoder.
     * Handles two-level selective disclosure by re-decoding nested maps whose
     * _sd arrays were not resolved during the first pass.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> extractDisclosedClaims(String sdJwt) {
        try {
            // Parse the SD-JWT to get credential JWT and disclosures
            SDJWT vp = SDJWT.parse(sdJwt);

            // Parse credential JWT payload to get the encoded structure with _sd arrays
            String[] jwtParts = vp.getCredentialJwt().split("\\.");
            String payloadJson = new String(Base64.getUrlDecoder().decode(jwtParts[1]));
            Map<String, Object> payload = objectMapper.readValue(payloadJson, new TypeReference<>() {});

            // Get the list of disclosures from the VP
            List<Disclosure> disclosures = vp.getDisclosures();

            // First pass: decode top-level _sd entries
            SDObjectDecoder decoder = new SDObjectDecoder();
            Map<String, Object> decoded = decoder.decode(payload, disclosures);

            // Second pass: re-decode any nested map that still has an _sd key
            for (Map.Entry<String, Object> entry : decoded.entrySet()) {
                if (entry.getValue() instanceof Map) {
                    Map<String, Object> nested = (Map<String, Object>) entry.getValue();
                    if (nested.containsKey("_sd")) {
                        entry.setValue(decoder.decode(nested, disclosures));
                    }
                }
            }

            // Clean up _sd artifacts from all levels
            cleanSdArtifacts(decoded);

            logger.debug("Extracted claims: {}", decoded.keySet());
            return decoded;

        } catch (Exception e) {
            logger.error("Error extracting disclosed claims", e);
            return Map.of();
        }
    }

    /**
     * Recursively removes _sd and _sd_alg artifacts from decoded claims.
     */
    @SuppressWarnings("unchecked")
    private void cleanSdArtifacts(Map<String, Object> map) {
        map.remove("_sd");
        map.remove("_sd_alg");
        for (Object value : map.values()) {
            if (value instanceof Map) {
                cleanSdArtifacts((Map<String, Object>) value);
            }
        }
    }

}
