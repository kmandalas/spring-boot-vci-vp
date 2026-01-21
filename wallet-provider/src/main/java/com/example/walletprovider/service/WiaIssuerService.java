package com.example.walletprovider.service;

import com.example.walletprovider.config.WpMetadataConfig;
import com.example.walletprovider.model.WiaCredentialRequest;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for issuing Wallet Instance Attestation (WIA) JWTs.
 * Per draft-ietf-oauth-attestation-based-client-auth.
 */
@Service
public class WiaIssuerService {

    private static final Logger logger = LoggerFactory.getLogger(WiaIssuerService.class);

    private final Set<String> usedNonces = ConcurrentHashMap.newKeySet();

    private final WpMetadataConfig wpMetadataConfig;
    private final WpSigningService wpSigningService;

    public WiaIssuerService(WpMetadataConfig wpMetadataConfig, WpSigningService wpSigningService) {
        this.wpMetadataConfig = wpMetadataConfig;
        this.wpSigningService = wpSigningService;
    }

    public String generateNonce() {
        return UUID.randomUUID().toString();
    }

    /**
     * Validates the WIA credential request and extracts the wallet's public key.
     *
     * @param request the WIA credential request
     * @return the wallet's public key from the proof JWT, or null if validation fails
     */
    public JWK validateCredentialRequest(WiaCredentialRequest request) {
        if (request == null || request.proof() == null || request.proof().jwt() == null) {
            logger.warn("Invalid request: missing proof or JWT");
            return null;
        }

        if (!"jwt".equals(request.proof().proofType())) {
            logger.warn("Invalid proof type: {}", request.proof().proofType());
            return null;
        }

        if (request.clientId() == null || request.clientId().isBlank()) {
            logger.warn("Invalid request: missing client_id");
            return null;
        }

        return validateProof(request.proof().jwt());
    }

    /**
     * Issues a WIA JWT for the given wallet public key and client_id.
     *
     * @param walletKey the wallet's public key (will be included in cnf.jwk)
     * @param clientId  the OAuth client_id
     * @return the issued WIA result containing the JWT and WIA ID
     */
    public WiaIssuanceResult issueWia(JWK walletKey, String clientId) throws JOSEException {
        UUID wiaId = UUID.randomUUID();
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(wpMetadataConfig.getTime().getWiaTtlSeconds(), ChronoUnit.SECONDS);

        String wiaJwt = generateWiaJwt(wiaId, walletKey, clientId, issuedAt, expiresAt);

        logger.info("Issued WIA: id={}, clientId={}, expires={}", wiaId, clientId, expiresAt);
        return new WiaIssuanceResult(wiaJwt, wiaId);
    }

    private String generateWiaJwt(UUID wiaId, JWK walletKey, String clientId,
                                   Instant issuedAt, Instant expiresAt) throws JOSEException {

        ECKey wpKey = wpSigningService.getSigningKey();

        // Build header with type "oauth-client-attestation+jwt" per spec
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(wpKey.getKeyID())
                .type(new JOSEObjectType("oauth-client-attestation+jwt"))
                .x509CertChain(wpSigningService.getX5cChain())
                .build();

        // Build cnf claim with wallet's public key (RFC 7800)
        Map<String, Object> cnf = new LinkedHashMap<>();
        cnf.put("jwk", walletKey.toPublicJWK().toJSONObject());

        // EUDI: general_info (same structure as WUA but without WSCD info)
        Map<String, Object> generalInfo = new LinkedHashMap<>();
        generalInfo.put("wallet_provider_name", wpMetadataConfig.getProvider().getName());
        generalInfo.put("wallet_solution_id", wpMetadataConfig.getProvider().getId());
        generalInfo.put("wallet_solution_version", wpMetadataConfig.getProvider().getSolutionVersion());
        generalInfo.put("wallet_solution_certification_information", wpMetadataConfig.getProvider().getCertificationInformation());

        // EUDI: eudi_wallet_info (WIA doesn't include wscd_info since no key attestation)
        Map<String, Object> eudiWalletInfo = new LinkedHashMap<>();
        eudiWalletInfo.put("general_info", generalInfo);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(wpMetadataConfig.getClaims().getIss())
                .subject(clientId)
                .jwtID(wiaId.toString())
                .issueTime(Date.from(issuedAt))
                .notBeforeTime(Date.from(issuedAt))  // EUDI: nbf claim
                .expirationTime(Date.from(expiresAt))
                .claim("cnf", cnf)
                .claim("eudi_wallet_info", eudiWalletInfo)
                .build();

        // Sign JWT with Wallet Provider's key
        SignedJWT signedJWT = new SignedJWT(header, claims);
        JWSSigner signer = new ECDSASigner(wpKey);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    private JWK validateProof(String proofJwt) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(proofJwt);
            JWSHeader header = signedJWT.getHeader();

            // Reject 'none' and symmetric algorithms
            JWSAlgorithm algorithm = header.getAlgorithm();
            if (algorithm == JWSAlgorithm.NONE || algorithm.getName().startsWith("HS")) {
                logger.warn("Rejected algorithm: {}", algorithm);
                return null;
            }

            // Verify type (using same type as WUA for proof)
            if (header.getType() == null || !"openid4vci-proof+jwt".equals(header.getType().toString())) {
                logger.warn("Invalid proof type header: {}", header.getType());
                return null;
            }

            // Either kid or jwk, not both
            if (header.getKeyID() != null && header.getJWK() != null) {
                logger.warn("Both kid and jwk present in header");
                return null;
            }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            // Validate audience
            if (!claims.getAudience().contains(wpMetadataConfig.getClaims().getAudience())) {
                logger.warn("Invalid audience: {}", claims.getAudience());
                return null;
            }

            // Validate issuance time
            Date issuedAt = claims.getIssueTime();
            long maxProofAge = wpMetadataConfig.getTime().getMaxProofAgeSeconds();
            if (issuedAt == null || issuedAt.toInstant().isBefore(
                    Instant.now().minus(maxProofAge, ChronoUnit.SECONDS))) {
                logger.warn("Proof JWT too old or missing iat");
                return null;
            }

            // Validate nonce
            String nonce = claims.getStringClaim("nonce");
            if (nonce != null && !isValidNonce(nonce)) {
                logger.warn("Invalid or reused nonce");
                return null;
            }

            // Extract wallet public key
            JWK walletJwk = header.getJWK();
            if (walletJwk == null) {
                logger.warn("Missing JWK in proof header");
                return null;
            }

            // Verify signature
            if (!verifySignatureWithProvidedJwk(signedJWT, walletJwk)) {
                logger.warn("Proof signature verification failed");
                return null;
            }

            return walletJwk;

        } catch (Exception e) {
            logger.error("Error validating proof JWT", e);
            return null;
        }
    }

    private boolean isValidNonce(String nonce) {
        if (nonce == null) {
            return false;
        }
        if (usedNonces.contains(nonce)) {
            return false;
        }
        usedNonces.add(nonce);
        return true;
    }

    private boolean verifySignatureWithProvidedJwk(SignedJWT signedJWT, JWK jwk) {
        try {
            if (jwk.getKeyType() == KeyType.RSA) {
                RSAPublicKey publicKey = ((RSAKey) jwk).toRSAPublicKey();
                JWSVerifier verifier = new RSASSAVerifier(publicKey);
                return signedJWT.verify(verifier);
            } else if (jwk.getKeyType() == KeyType.EC) {
                ECPublicKey publicKey = ((ECKey) jwk).toECPublicKey();
                JWSVerifier verifier = new ECDSAVerifier(publicKey);
                return signedJWT.verify(verifier);
            }
            return false;
        } catch (Exception e) {
            logger.error("Error verifying signature", e);
            return false;
        }
    }

    public record WiaIssuanceResult(String wiaJwt, UUID wiaId) {}

}
