package com.example.verifier.service;

import com.authlete.sd.SDJWT;
import com.example.verifier.config.AppConfig;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.*;

@Service
public class VpValidationService {

    private static final Logger logger = LoggerFactory.getLogger(VpValidationService.class);

    private final AppConfig appConfig;
    private final AuthleteHelper authleteHelper;
    private final ObjectMapper objectMapper;

    public VpValidationService(AppConfig appConfig, AuthleteHelper authleteHelper, ObjectMapper objectMapper) {
        this.appConfig = appConfig;
        this.authleteHelper = authleteHelper;
        this.objectMapper = objectMapper;
    }

    /**
     * Result of VP validation containing status and disclosed claims.
     */
    public record ValidationResult(boolean valid, String issuer, Map<String, String> disclosedClaims, String error) {
        public static ValidationResult success(String issuer, Map<String, String> claims) {
            return new ValidationResult(true, issuer, claims, null);
        }

        public static ValidationResult failure(String error) {
            return new ValidationResult(false, null, Map.of(), error);
        }
    }

    /**
     * Validates a VP token and extracts disclosed claims.
     *
     * @param vpToken the SD-JWT VP token
     * @return ValidationResult with status and claims
     */
    public ValidationResult validateAndExtract(String vpToken) {
        try {
            // Step 1: Parse the VP Token
            SDJWT vp = SDJWT.parse(vpToken);

            // Step 2: Parse credential JWT to extract issuer
            SignedJWT credentialJwt = SignedJWT.parse(vp.getCredentialJwt());

            // Step 3: Validate issuer against local "trusted list"
            String issuer = credentialJwt.getJWTClaimsSet().getIssuer();
            if (!appConfig.isTrustedIssuer(issuer)) {
                logger.warn("⚠️Untrusted credential issuer: {}", issuer);
                return ValidationResult.failure("Untrusted credential issuer: " + issuer);
            }
            logger.info("Credential issuer '{}' is trusted", issuer);

            // Step 4: Fetch issuer's public key from JWKS endpoint (key pinning)
            String jwksUrl = issuer + "/.well-known/jwks.json";
            logger.debug("Fetching issuer JWKS from: {}", jwksUrl);
            JWKSet issuerJwkSet = JWKSet.load(new URL(jwksUrl));
            JWK jwksKey = issuerJwkSet.getKeys().get(0);
            logger.info("Loaded issuer public key from JWKS");

            // Step 5: Extract public key from x5c and cross-check with JWKS
            JWK x5cKey = extractKeyFromX5c(credentialJwt);
            if (x5cKey == null) {
                return ValidationResult.failure("Failed to extract key from x5c header");
            }
            if (!keysMatch(jwksKey, x5cKey)) {
                logger.warn("⚠️x5c key does not match JWKS key - possible tampering");
                return ValidationResult.failure("x5c key does not match issuer JWKS");
            }
            logger.info("x5c key matches JWKS key - cross-check passed");

            // Step 6: Verify VP (credential signature + key binding JWT)
            authleteHelper.verifyVP(vp, jwksKey);
            logger.info("VP signature verification successful");

            // Step 7: Extract disclosed claims
            Map<String, String> claims = extractDisclosedClaims(vpToken);

            return ValidationResult.success(issuer, claims);

        } catch (Exception e) {
            logger.error("❌VP validation failed", e);
            return ValidationResult.failure(e.getMessage());
        }
    }

    /**
     * Extracts the issuer's public key from the x5c certificate chain in the JWT header.
     */
    private JWK extractKeyFromX5c(SignedJWT credentialJwt) {
        try {
            List<com.nimbusds.jose.util.Base64> x5cChain = credentialJwt.getHeader().getX509CertChain();
            if (x5cChain == null || x5cChain.isEmpty()) {
                logger.error("❌No x5c certificate chain in credential JWT header");
                return null;
            }

            // Parse leaf certificate (first in chain)
            byte[] certBytes = x5cChain.get(0).decode();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(certBytes));

            // Extract EC public key and build JWK
            ECPublicKey ecPublicKey = (ECPublicKey) certificate.getPublicKey();
            logger.debug("Extracted issuer public key from x5c header");

            return new ECKey.Builder(Curve.P_256, ecPublicKey).build();

        } catch (Exception e) {
            logger.error("❌Failed to extract key from x5c", e);
            return null;
        }
    }

    /**
     * Compares two JWKs by their public key thumbprint.
     */
    private boolean keysMatch(JWK jwksKey, JWK x5cKey) {
        try {
            String jwksThumbprint = jwksKey.computeThumbprint().toString();
            String x5cThumbprint = x5cKey.computeThumbprint().toString();
            return jwksThumbprint.equals(x5cThumbprint);
        } catch (Exception e) {
            logger.error("❌Failed to compute key thumbprints", e);
            return false;
        }
    }

    /**
     * Extracts disclosed claims from an SD-JWT VP token.
     */
    private Map<String, String> extractDisclosedClaims(String sdJwt) {
        Map<String, String> claims = new LinkedHashMap<>();

        String[] parts = sdJwt.split("~", -1);
        List<String> disclosures = Arrays.stream(parts)
                .skip(1)
                .filter(d -> !d.isEmpty() && !d.contains("."))  // Skip empty and JWT-style
                .toList();

        for (String disclosure : disclosures) {
            try {
                byte[] decodedBytes = Base64.getUrlDecoder().decode(disclosure);
                String decodedJson = new String(decodedBytes);
                List<String> claimData = objectMapper.readValue(decodedJson, new TypeReference<>() {});

                if (claimData.size() >= 3) {
                    claims.put(claimData.get(1), claimData.get(2));
                }
            } catch (Exception e) {
                logger.warn("⚠️Error decoding disclosure: {}", disclosure);
            }
        }

        logger.info("Extracted {} disclosed claims", claims.size());
        return claims;
    }

    /**
     * Extracts the VP token from various formats (String or DCQL Map).
     */
    @SuppressWarnings("unchecked")
    public String extractVpToken(Object vpTokenObj) {
        if (vpTokenObj == null) {
            return null;
        }

        // String format (backward compatibility)
        if (vpTokenObj instanceof String) {
            return (String) vpTokenObj;
        }

        // DCQL format: Map<QueryId, List<VP>>
        if (vpTokenObj instanceof Map) {
            Map<String, Object> vpTokenMap = (Map<String, Object>) vpTokenObj;
            for (Object value : vpTokenMap.values()) {
                if (value instanceof List<?> vpList) {
                    if (!vpList.isEmpty() && vpList.get(0) instanceof String) {
                        return (String) vpList.get(0);
                    }
                }
            }
        }

        return null;
    }

}
