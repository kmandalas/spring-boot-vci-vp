package com.example.issuer.service;

import com.authlete.sd.SDJWT;
import com.example.issuer.config.AppMetadataConfig;
import com.example.issuer.model.CredentialRequest;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.example.issuer.config.WalletProviderConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class CredentialIssuerService {

    private static final Logger logger = LoggerFactory.getLogger(CredentialIssuerService.class);

    // Maximum age of a JWT proof in seconds (5 minutes)
    private static final long MAX_PROOF_AGE_SECONDS = 300;

    private final Set<String> usedNonces = ConcurrentHashMap.newKeySet();

    private final AuthleteHelper authleteHelper;
    private final AppMetadataConfig appMetadataConfig;
    private final WalletProviderConfig walletProviderConfig;

    public CredentialIssuerService(AuthleteHelper authleteHelper, AppMetadataConfig appMetadataConfig,
                                   WalletProviderConfig walletProviderConfig) {
        this.authleteHelper = authleteHelper;
        this.appMetadataConfig = appMetadataConfig;
        this.walletProviderConfig = walletProviderConfig;
    }

    // Nonce
    public String generateCredentialNonce() {
        // Generate a random nonce
        String nonce = java.util.UUID.randomUUID().toString();

        // We don't add it to usedNonces yet, as it hasn't been used
        return nonce;
    }

    private boolean isValidNonce(String nonce) {
        if (nonce == null) {
            return false;
        }

        // Check if nonce was used before (prevent replay attacks)
        if (usedNonces.contains(nonce)) {
            return false;
        }

        // Store nonce as used
        usedNonces.add(nonce);
        return true;
    }

    // Validation
    public JWK validateCredentialRequest(CredentialRequest request) {
        if (request == null || request.proof() == null || request.proof().jwt() == null) {
            return null;
        }

        // Check that proof type is "jwt"
        if (!"jwt".equals(request.proof().proofType())) {
            return null;
        }

        String proofJwt = request.proof().jwt();
        return validateProof(proofJwt);
    } // todo - check also format, credentialConfigurationId?

    private JWK validateProof(String proofJwt) {
        try {
            // Parse the JWT
            SignedJWT signedJWT = SignedJWT.parse(proofJwt);

            // 1. Validate JOSE Header
            JWSHeader header = signedJWT.getHeader();

            // Ensure algorithm is not 'none' and not a symmetric algorithm
            JWSAlgorithm algorithm = header.getAlgorithm();
            if (algorithm == JWSAlgorithm.NONE || algorithm.getName().startsWith("HS")) {
                logger.warn("Rejected algorithm: {}", algorithm);
                return null;
            }

            // Verify that the type is "openid4vci-proof+jwt"
            if (!"openid4vci-proof+jwt".equals(header.getType().toString())) {
                logger.warn("Invalid proof type: {}", header.getType());
                return null;
            }

            // 2. Validate JWT Claims
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            // Validate audience (must be the Credential Issuer Identifier)
            if (!claims.getAudience().contains(appMetadataConfig.getClaims().getAudience())) {
                logger.warn("Invalid audience: {}", claims.getAudience());
                return null;
            }

            // Validate issuance time (should be recent)
            Date issuedAt = claims.getIssueTime();
            if (issuedAt == null || issuedAt.toInstant().isBefore(
                    Instant.now().minus(MAX_PROOF_AGE_SECONDS, ChronoUnit.SECONDS))) {
                logger.warn("Proof JWT too old or missing iat");
                return null;
            }

            // Validate nonce to prevent replay attacks
            String nonce = claims.getStringClaim("nonce");
            if (nonce != null && !isValidNonce(nonce)) {
                logger.warn("Invalid or reused nonce");
                return null;
            }

            // 3. Extract Wallet Public Key - check for key_attestation (WUA) first
            JWK walletJwk;
            String keyAttestation = (String) header.getCustomParam("key_attestation");

            if (keyAttestation != null) {
                // WUA present - extract key from attested_keys
                logger.info("Processing credential request with WUA (key_attestation)");
                walletJwk = extractKeyFromWua(header, keyAttestation);
                if (walletJwk == null) {
                    return null;
                }
            } else {
                // Fallback to jwk header (backward compatibility)
                walletJwk = header.getJWK();
                if (walletJwk == null) {
                    logger.warn("Missing both key_attestation and jwk in proof header");
                    return null;
                }
                logger.info("Processing credential request with inline JWK (no WUA)");
            }

            // 4. Verify Signature using the extracted wallet key
            boolean isValid = verifySignatureWithProvidedJwk(signedJWT, walletJwk);
            if (!isValid) {
                logger.warn("Proof signature verification failed");
            }
            return isValid ? walletJwk : null;

        } catch (Exception e) {
            logger.error("Error validating proof JWT", e);
            return null;
        }
    }

    /**
     * Extract wallet public key from WUA (Wallet Unit Attestation).
     * Dynamically discovers Wallet Provider JWKS from WUA's iss claim.
     * Validates issuer against trusted list and checks WSCD type policy.
     */
    @SuppressWarnings("unchecked")
    private JWK extractKeyFromWua(JWSHeader outerHeader, String keyAttestation) {
        try {
            // 1. Parse WUA JWT
            SignedJWT wuaJwt = SignedJWT.parse(keyAttestation);
            JWTClaimsSet wuaClaims = wuaJwt.getJWTClaimsSet();

            // 2. Extract and validate WUA issuer
            String wuaIssuer = wuaClaims.getIssuer();
            if (!walletProviderConfig.isTrustedIssuer(wuaIssuer)) {
                logger.warn("Untrusted WUA issuer: {}", wuaIssuer);
                return null;
            }
            logger.debug("WUA issuer '{}' is trusted", wuaIssuer);

            // 3. Derive JWKS URL from issuer and fetch Wallet Provider's public key
            String jwksUrl = wuaIssuer + "/.well-known/jwks.json";
            JWKSet wpJwkSet = JWKSet.load(new URL(jwksUrl));
            JWK wpJwksKey = wpJwkSet.getKeys().get(0);

            // 4. Extract x5c from WUA header and cross-check with JWKS (if present)
            JWK x5cKey = extractKeyFromX5c(wuaJwt);
            if (x5cKey != null) {
                if (!keysMatch(wpJwksKey, x5cKey)) {
                    logger.warn("WUA x5c key does not match Wallet Provider JWKS - possible tampering");
                    return null;
                }
                logger.debug("WUA x5c key matches JWKS key - cross-check passed");
            } else {
                logger.debug("No x5c in WUA header, using JWKS key only");
            }

            // 5. Verify WUA signature
            if (!verifySignatureWithProvidedJwk(wuaJwt, wpJwksKey)) {
                logger.warn("WUA signature verification failed");
                return null;
            }
            logger.debug("WUA signature verified successfully");

            // 6. Check WSCD type policy
            if (!isWscdTypePolicyCompliant(wuaClaims)) {
                return null;
            }

            // 7. Extract attested_keys array from WUA
            List<Map<String, Object>> attestedKeys = (List<Map<String, Object>>) wuaClaims.getClaim("attested_keys");
            if (attestedKeys == null || attestedKeys.isEmpty()) {
                logger.warn("No attested_keys in WUA");
                return null;
            }

            // 8. Use kid from JWT proof header to index into attested_keys
            String kid = outerHeader.getKeyID();
            int keyIndex = 0;
            if (kid != null) {
                try {
                    keyIndex = Integer.parseInt(kid);
                } catch (NumberFormatException e) {
                    logger.warn("Invalid kid format '{}', using index 0", kid);
                }
            }

            if (keyIndex >= attestedKeys.size()) {
                logger.warn("Key index {} out of bounds (attested_keys size: {})", keyIndex, attestedKeys.size());
                return null;
            }

            // 9. Parse and return the JWK
            Map<String, Object> keyMap = attestedKeys.get(keyIndex);
            JWK walletJwk = JWK.parse(keyMap);
            logger.debug("Extracted wallet key from WUA attested_keys[{}]", keyIndex);

            return walletJwk;

        } catch (Exception e) {
            logger.error("Error extracting key from WUA", e);
            return null;
        }
    }

    private boolean verifySignatureWithProvidedJwk(SignedJWT signedJWT, JWK jwk) {
        try {
            // Handle different key types
            if (jwk.getKeyType() == KeyType.RSA) {
                RSAPublicKey publicKey = ((RSAKey)jwk).toRSAPublicKey();
                JWSVerifier verifier = new RSASSAVerifier(publicKey);
                return signedJWT.verify(verifier);
            }
            else if (jwk.getKeyType() == KeyType.EC) {
                ECPublicKey publicKey = ((ECKey)jwk).toECPublicKey();
                JWSVerifier verifier = new ECDSAVerifier(publicKey);
                return signedJWT.verify(verifier);
            }
            // Add other key types as needed (EdDSA, etc.)

            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Extracts the public key from the x5c certificate chain in the JWT header.
     * Returns null if no x5c is present.
     */
    private JWK extractKeyFromX5c(SignedJWT signedJWT) {
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

            // Extract EC public key and build JWK
            ECPublicKey ecPublicKey = (ECPublicKey) certificate.getPublicKey();
            return new ECKey.Builder(Curve.P_256, ecPublicKey).build();

        } catch (Exception e) {
            logger.error("Failed to extract key from x5c", e);
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
            logger.error("Failed to compute key thumbprints", e);
            return false;
        }
    }

    /**
     * Validates WSCD type from WUA against configured policy.
     * Extracts wscd_type from eudi_wallet_info.key_storage_info.storage_certification_information.
     *
     * @param wuaClaims the WUA JWT claims
     * @return true if WSCD type is allowed by policy, false otherwise
     */
    @SuppressWarnings("unchecked")
    private boolean isWscdTypePolicyCompliant(JWTClaimsSet wuaClaims) {
        Map<String, Object> eudiWalletInfo = (Map<String, Object>) wuaClaims.getClaim("eudi_wallet_info");
        if (eudiWalletInfo == null) {
            logger.debug("No eudi_wallet_info in WUA, skipping WSCD policy check");
            return true;
        }

        Map<String, Object> keyStorageInfo = (Map<String, Object>) eudiWalletInfo.get("key_storage_info");
        if (keyStorageInfo == null) {
            logger.debug("No key_storage_info in WUA, skipping WSCD policy check");
            return true;
        }

        Map<String, Object> storageCertInfo = (Map<String, Object>) keyStorageInfo.get("storage_certification_information");
        if (storageCertInfo == null) {
            logger.debug("No storage_certification_information in WUA, skipping WSCD policy check");
            return true;
        }

        String wscdType = (String) storageCertInfo.get("wscd_type");
        String securityLevel = (String) storageCertInfo.get("security_level");
        logger.info("WUA WSCD type: {}, security level: {}", wscdType, securityLevel);

        if (!walletProviderConfig.isWscdTypeAllowed(wscdType)) {
            logger.warn("WSCD type '{}' not allowed by policy (allowed: {})",
                    wscdType, walletProviderConfig.getAllowedWscdTypes());
            return false;
        }

        return true;
    }

    // Issuance
    public String generateSdJwt(JWK walletKey, String userIdentifier) throws JOSEException, ParseException {
        // Step 1: Ensure wallet key is provided
        if (walletKey == null) {
            throw new IllegalArgumentException("Wallet key is required for SD-JWT issuance.");
        }

        // Step 2: Create SD-JWT Verifiable Credential (signing key loaded via IssuerSigningService)
        SDJWT sdJwt = authleteHelper.createVC(walletKey.toPublicJWK(), userIdentifier);

        // Step 3: Return serialized SD-JWT
        return sdJwt.toString();
    }

}
