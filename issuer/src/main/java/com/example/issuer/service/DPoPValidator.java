package com.example.issuer.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;
import java.util.Set;

/**
 * Validates DPoP (Demonstrating Proof-of-Possession) proofs per RFC 9449.
 *
 * NOTE: Kept for reference. Spring Security 6.5+ has built-in DPoP support.
 */
// @Service  // Disabled - using Spring Security's built-in DPoP support
public class DPoPValidator {

    private static final Logger log = LoggerFactory.getLogger(DPoPValidator.class);

    private static final long MAX_DPOP_AGE_SECONDS = 300; // 5 minutes
    private static final Set<JWSAlgorithm> ALLOWED_ALGORITHMS = Set.of(JWSAlgorithm.ES256);

    /**
     * Validates a DPoP proof JWT.
     *
     * @param dpopProof   The DPoP header value
     * @param httpMethod  The HTTP method (e.g., "POST")
     * @param httpUri     The request URI (e.g., "http://localhost:8080/credential")
     * @param expectedJkt The expected JWK thumbprint from access token's cnf.jkt
     * @return true if valid
     */
    public boolean validate(String dpopProof, String httpMethod, String httpUri, String expectedJkt) {
        if (dpopProof == null || dpopProof.isBlank()) {
            log.warn("DPoP proof is missing");
            return false;
        }

        try {
            SignedJWT jwt = SignedJWT.parse(dpopProof);
            JWSHeader header = jwt.getHeader();
            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            // 1. Validate type
            if (header.getType() == null || !"dpop+jwt".equals(header.getType().toString())) {
                log.warn("Invalid DPoP type: {}", header.getType());
                return false;
            }

            // 2. Validate algorithm (HAIP requires ES256)
            if (!ALLOWED_ALGORITHMS.contains(header.getAlgorithm())) {
                log.warn("Disallowed DPoP algorithm: {}", header.getAlgorithm());
                return false;
            }

            // 3. Extract JWK from header
            JWK jwk = header.getJWK();
            if (jwk == null) {
                log.warn("DPoP proof missing jwk in header");
                return false;
            }

            // 4. Ensure no private key material
            if (jwk.isPrivate()) {
                log.warn("DPoP jwk contains private key material");
                return false;
            }

            // 5. Verify thumbprint matches token's cnf.jkt
            String thumbprint = jwk.computeThumbprint().toString();
            if (!thumbprint.equals(expectedJkt)) {
                log.warn("DPoP thumbprint mismatch. Expected: {}, Got: {}", expectedJkt, thumbprint);
                return false;
            }

            // 6. Verify signature
            if (jwk instanceof ECKey ecKey) {
                ECDSAVerifier verifier = new ECDSAVerifier(ecKey);
                if (!jwt.verify(verifier)) {
                    log.warn("DPoP signature verification failed");
                    return false;
                }
            } else {
                log.warn("Unsupported key type: {}", jwk.getKeyType());
                return false;
            }

            // 7. Validate htm (HTTP method)
            String htm = claims.getStringClaim("htm");
            if (!httpMethod.equalsIgnoreCase(htm)) {
                log.warn("DPoP htm mismatch. Expected: {}, Got: {}", httpMethod, htm);
                return false;
            }

            // 8. Validate htu (HTTP URI)
            String htu = claims.getStringClaim("htu");
            if (!normalizeUri(httpUri).equals(normalizeUri(htu))) {
                log.warn("DPoP htu mismatch. Expected: {}, Got: {}", httpUri, htu);
                return false;
            }

            // 9. Validate iat (freshness)
            if (claims.getIssueTime() == null) {
                log.warn("DPoP missing iat claim");
                return false;
            }
            Instant iat = claims.getIssueTime().toInstant();
            Instant now = Instant.now();
            if (iat.isAfter(now.plusSeconds(60))) {
                log.warn("DPoP iat is in the future");
                return false;
            }
            if (iat.isBefore(now.minusSeconds(MAX_DPOP_AGE_SECONDS))) {
                log.warn("DPoP proof expired");
                return false;
            }

            // 10. Validate jti exists (replay prevention)
            String jti = claims.getJWTID();
            if (jti == null || jti.isBlank()) {
                log.warn("DPoP jti claim missing");
                return false;
            }

            // TODO: Store jti for replay prevention in production

            log.debug("DPoP proof validated successfully");
            return true;

        } catch (ParseException | JOSEException e) {
            log.error("Error validating DPoP proof", e);
            return false;
        }
    }

    private String normalizeUri(String uri) {
        if (uri == null) return "";
        int queryIndex = uri.indexOf('?');
        if (queryIndex > 0) {
            uri = uri.substring(0, queryIndex);
        }
        int fragmentIndex = uri.indexOf('#');
        if (fragmentIndex > 0) {
            uri = uri.substring(0, fragmentIndex);
        }
        return uri;
    }
}
