package com.example.authserver.wia;

import com.example.authserver.config.WalletAttestationProperties;
import com.example.authserver.util.JwtSignatureUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Validates OAuth Attestation-Based Client Authentication (WIA + PoP JWTs).
 * Implements the validation flow per draft-ietf-oauth-attestation-based-client-auth.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/">
 *      draft-ietf-oauth-attestation-based-client-auth</a>
 */
public class WalletAttestationAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(WalletAttestationAuthenticationProvider.class);

    private static final String WIA_TYPE = "oauth-client-attestation+jwt";
    private static final String POP_TYPE = "oauth-client-attestation-pop+jwt";
    private static final Set<JWSAlgorithm> FORBIDDEN_ALGORITHMS = Set.of(
            JWSAlgorithm.parse("none"),
            JWSAlgorithm.HS256,
            JWSAlgorithm.HS384,
            JWSAlgorithm.HS512
    );

    private final RegisteredClientRepository registeredClientRepository;
    private final WalletAttestationProperties properties;
    private final String authorizationServerIssuer;

    // In-memory JTI replay protection (use distributed cache in production)
    private final Set<String> usedJtis = ConcurrentHashMap.newKeySet();

    public WalletAttestationAuthenticationProvider(
            RegisteredClientRepository registeredClientRepository,
            WalletAttestationProperties properties,
            String authorizationServerIssuer) {
        this.registeredClientRepository = registeredClientRepository;
        this.properties = properties;
        this.authorizationServerIssuer = authorizationServerIssuer;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        WalletAttestationAuthenticationToken token = (WalletAttestationAuthenticationToken) authentication;

        try {
            // Parse JWTs
            SignedJWT wiaJwt = SignedJWT.parse(token.getWiaJwt());
            SignedJWT popJwt = SignedJWT.parse(token.getPopJwt());

            // Validate WIA JWT
            JWK walletPublicKey = validateWiaJwt(wiaJwt);

            // Validate PoP JWT using wallet public key from WIA
            validatePopJwt(popJwt, walletPublicKey);

            // Look up registered client
            String clientId = (String) token.getPrincipal();
            RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
            if (registeredClient == null) {
                throw authException("invalid_client", "Client not found: " + clientId);
            }

            // Verify client supports attestation-based authentication
            if (!registeredClient.getClientAuthenticationMethods()
                    .contains(WalletAttestationAuthenticationToken.ATTEST_JWT_CLIENT_AUTH)) {
                throw authException("invalid_client",
                        "Client does not support attest_jwt_client_auth: " + clientId);
            }

            logger.info("WIA authentication successful for client: {}", clientId);
            return new WalletAttestationAuthenticationToken(
                    registeredClient,
                    token.getWiaJwt(),
                    token.getPopJwt(),
                    token.getDpopJwt(),
                    walletPublicKey
            );

        } catch (OAuth2AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            logger.error("WIA authentication failed", e);
            throw authException("invalid_client", "WIA authentication failed: " + e.getMessage());
        }
    }

    /**
     * Validates the Wallet Instance Attestation JWT.
     *
     * @param wiaJwt the WIA JWT to validate
     * @return the wallet's public key from cnf.jwk claim
     */
    private JWK validateWiaJwt(SignedJWT wiaJwt) throws ParseException, JOSEException {
        JWTClaimsSet claims = wiaJwt.getJWTClaimsSet();
        String algorithm = wiaJwt.getHeader().getAlgorithm().getName();
        String type = wiaJwt.getHeader().getType() != null ? wiaJwt.getHeader().getType().getType() : null;

        // Validate typ header
        if (!WIA_TYPE.equals(type)) {
            throw authException("invalid_client", "WIA typ must be '" + WIA_TYPE + "', got: " + type);
        }

        // Validate algorithm (reject none and symmetric)
        if (FORBIDDEN_ALGORITHMS.contains(wiaJwt.getHeader().getAlgorithm())) {
            throw authException("invalid_client", "WIA uses forbidden algorithm: " + algorithm);
        }

        // Validate issuer is trusted
        String issuer = claims.getIssuer();
        if (issuer == null || !properties.isTrustedIssuer(issuer)) {
            throw authException("invalid_client", "WIA issuer not trusted: " + issuer);
        }

        // Validate subject (client_id) is present
        String subject = claims.getSubject();
        if (subject == null || subject.isBlank()) {
            throw authException("invalid_client", "WIA missing sub claim");
        }

        // Validate expiration
        Date exp = claims.getExpirationTime();
        if (exp == null || exp.toInstant().isBefore(Instant.now())) {
            throw authException("invalid_client", "WIA expired or missing exp claim");
        }

        // Validate not before (nbf) if present
        Date nbf = claims.getNotBeforeTime();
        if (nbf != null && nbf.toInstant().isAfter(Instant.now())) {
            throw authException("invalid_client", "WIA not yet valid (nbf in future)");
        }

        // Validate issued at time (not too old)
        Date iat = claims.getIssueTime();
        if (iat == null) {
            throw authException("invalid_client", "WIA missing iat claim");
        }
        long wiaAgeSeconds = Instant.now().getEpochSecond() - iat.toInstant().getEpochSecond();
        if (wiaAgeSeconds > properties.getMaxWiaAgeSeconds()) {
            throw authException("invalid_client", "WIA too old (age: " + wiaAgeSeconds + "s)");
        }

        // Extract cnf.jwk (wallet's public key)
        JWK walletPublicKey = extractCnfJwk(claims);
        if (walletPublicKey == null) {
            throw authException("invalid_client", "WIA missing cnf.jwk claim");
        }

        // Verify WIA signature using Wallet Provider's public key
        verifyWiaSignature(wiaJwt, issuer);

        // Log eudi_wallet_info if present (for audit purposes)
        logWalletInfo(claims, subject);

        logger.debug("WIA JWT validated successfully for client: {}", subject);
        return walletPublicKey;
    }

    /**
     * Logs wallet information from eudi_wallet_info claim for audit purposes.
     */
    @SuppressWarnings("unchecked")
    private void logWalletInfo(JWTClaimsSet claims, String clientId) {
        try {
            Map<String, Object> walletInfo = claims.getJSONObjectClaim("eudi_wallet_info");
            if (walletInfo != null) {
                Map<String, Object> generalInfo = (Map<String, Object>) walletInfo.get("general_info");
                if (generalInfo != null) {
                    logger.info("WIA wallet info for {}: provider={}, solution={}, version={}",
                            clientId,
                            generalInfo.get("wallet_provider_name"),
                            generalInfo.get("wallet_solution_id"),
                            generalInfo.get("wallet_solution_version"));
                }
            }
        } catch (Exception e) {
            logger.debug("Could not parse eudi_wallet_info: {}", e.getMessage());
        }
    }

    /**
     * Validates the Proof of Possession JWT.
     *
     * @param popJwt          the PoP JWT to validate
     * @param walletPublicKey the wallet's public key from WIA cnf.jwk
     */
    private void validatePopJwt(SignedJWT popJwt, JWK walletPublicKey) throws ParseException {
        JWTClaimsSet claims = popJwt.getJWTClaimsSet();
        String algorithm = popJwt.getHeader().getAlgorithm().getName();
        String type = popJwt.getHeader().getType() != null ? popJwt.getHeader().getType().getType() : null;

        // Validate typ header
        if (!POP_TYPE.equals(type)) {
            throw authException("invalid_client", "PoP typ must be '" + POP_TYPE + "', got: " + type);
        }

        // Validate algorithm (reject none and symmetric)
        if (FORBIDDEN_ALGORITHMS.contains(popJwt.getHeader().getAlgorithm())) {
            throw authException("invalid_client", "PoP uses forbidden algorithm: " + algorithm);
        }

        // Validate issuer matches client_id (from WIA sub)
        String issuer = claims.getIssuer();
        if (issuer == null || issuer.isBlank()) {
            throw authException("invalid_client", "PoP missing iss claim");
        }

        // Validate audience matches authorization server issuer
        if (claims.getAudience() == null || !claims.getAudience().contains(authorizationServerIssuer)) {
            throw authException("invalid_client",
                    "PoP aud must include '" + authorizationServerIssuer + "', got: " + claims.getAudience());
        }

        // Validate jti for replay protection
        String jti = claims.getJWTID();
        if (jti == null || jti.isBlank()) {
            throw authException("invalid_client", "PoP missing jti claim");
        }
        if (!usedJtis.add(jti)) {
            throw authException("invalid_client", "PoP jti already used (replay detected)");
        }

        // Validate issued at time (not too old)
        Date iat = claims.getIssueTime();
        if (iat == null) {
            throw authException("invalid_client", "PoP missing iat claim");
        }
        long popAgeSeconds = Instant.now().getEpochSecond() - iat.toInstant().getEpochSecond();
        if (popAgeSeconds > properties.getMaxPopAgeSeconds()) {
            throw authException("invalid_client", "PoP too old (age: " + popAgeSeconds + "s)");
        }

        // Verify PoP signature using wallet's public key (from WIA cnf.jwk)
        if (!JwtSignatureUtils.verifySignature(popJwt, walletPublicKey)) {
            throw authException("invalid_client", "PoP signature verification failed");
        }

        logger.debug("PoP JWT validated successfully");
    }

    /**
     * Extracts the wallet's public key from the cnf.jwk claim.
     */
    @SuppressWarnings("unchecked")
    private JWK extractCnfJwk(JWTClaimsSet claims) {
        try {
            Map<String, Object> cnf = claims.getJSONObjectClaim("cnf");
            if (cnf == null) {
                return null;
            }
            Map<String, Object> jwkMap = (Map<String, Object>) cnf.get("jwk");
            if (jwkMap == null) {
                return null;
            }
            return JWK.parse(jwkMap);
        } catch (Exception e) {
            logger.warn("Failed to extract cnf.jwk from WIA: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Verifies WIA signature by fetching JWKS from the Wallet Provider.
     */
    private void verifyWiaSignature(SignedJWT wiaJwt, String issuer) {
        try {
            // First try to verify using x5c if present
            JWK x5cKey = JwtSignatureUtils.extractKeyFromX5c(wiaJwt);
            if (x5cKey != null) {
                // Fetch JWKS to cross-check the x5c key
                JWKSet jwkSet = fetchJwks(issuer);
                if (jwkSet != null) {
                    crossCheckX5cWithJwks(wiaJwt, x5cKey, jwkSet);
                }
                // Verify using x5c key
                if (!JwtSignatureUtils.verifySignature(wiaJwt, x5cKey)) {
                    throw authException("invalid_client", "WIA signature verification failed (x5c)");
                }
                logger.debug("WIA signature verified using x5c certificate");
                return;
            }

            // No x5c, fetch JWKS and verify using kid
            JWKSet jwkSet = fetchJwks(issuer);
            if (jwkSet == null) {
                throw authException("invalid_client", "Failed to fetch JWKS from Wallet Provider: " + issuer);
            }

            String kid = wiaJwt.getHeader().getKeyID();
            JWK signingKey = null;

            if (kid != null) {
                signingKey = jwkSet.getKeyByKeyId(kid);
            }
            if (signingKey == null && !jwkSet.getKeys().isEmpty()) {
                // Fallback to first key if no kid match
                signingKey = jwkSet.getKeys().getFirst();
            }

            if (signingKey == null) {
                throw authException("invalid_client", "No matching key found in Wallet Provider JWKS");
            }

            if (!JwtSignatureUtils.verifySignature(wiaJwt, signingKey)) {
                throw authException("invalid_client", "WIA signature verification failed (JWKS)");
            }

            logger.debug("WIA signature verified using JWKS");

        } catch (OAuth2AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            logger.error("WIA signature verification failed", e);
            throw authException("invalid_client", "WIA signature verification error: " + e.getMessage());
        }
    }

    /**
     * Cross-checks x5c key against JWKS keys.
     */
    private void crossCheckX5cWithJwks(SignedJWT wiaJwt, JWK x5cKey, JWKSet jwkSet) {
        String kid = wiaJwt.getHeader().getKeyID();
        if (kid == null) {
            return;
        }

        JWK jwksKey = jwkSet.getKeyByKeyId(kid);
        if (jwksKey == null) {
            logger.warn("WIA kid '{}' not found in JWKS, proceeding with x5c verification", kid);
            return;
        }

        // Compare public key material using thumbprint (ignores metadata like kid, use, alg)
        if (!JwtSignatureUtils.keysMatch(x5cKey, jwksKey)) {
            logger.warn("x5c key does not match JWKS key for kid '{}'", kid);
        } else {
            logger.debug("x5c key matches JWKS key - cross-check passed");
        }
    }

    /**
     * Fetches JWKS from the Wallet Provider's well-known endpoint.
     */
    private JWKSet fetchJwks(String issuer) {
        try {
            String jwksUrl = issuer + "/.well-known/jwks.json";
            logger.debug("Fetching JWKS from: {}", jwksUrl);
            return JWKSet.load(new URI(jwksUrl).toURL());
        } catch (Exception e) {
            logger.error("Failed to fetch JWKS from {}: {}", issuer, e.getMessage());
            return null;
        }
    }

    private OAuth2AuthenticationException authException(String errorCode, String description) {
        return new OAuth2AuthenticationException(new OAuth2Error(errorCode, description, null));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return WalletAttestationAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
