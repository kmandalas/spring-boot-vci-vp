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
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class CredentialIssuerService {

    // Maximum age of a JWT proof in seconds (5 minutes)
    private static final long MAX_PROOF_AGE_SECONDS = 300;

    private final Set<String> usedNonces = ConcurrentHashMap.newKeySet();

    private final AuthleteHelper authleteHelper;

    private final AppMetadataConfig appMetadataConfig;

    public CredentialIssuerService(AuthleteHelper authleteHelper, AppMetadataConfig appMetadataConfig) {
        this.authleteHelper = authleteHelper;
        this.appMetadataConfig = appMetadataConfig;
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
        if (request == null || request.getProof() == null || request.getProof().getJwt() == null) {
            return null;
        }

        // Check that proof type is "jwt"
        if (!"jwt".equals(request.getProof().getProofType())) {
            return null;
        }

        String proofJwt = request.getProof().getJwt();
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
                return null; // Reject JWT
            }

            // Verify that the type is "openid4vci-proof+jwt"
            if (!"openid4vci-proof+jwt".equals(header.getType().toString())) {
                return null;
            }

            // Ensure either `kid` or `jwk` is present, but not both
            if (header.getKeyID() != null && header.getJWK() != null) {
                return null;
            }

            // 2. Validate JWT Claims
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            // Validate audience (must be the Credential Issuer Identifier)
            if (!claims.getAudience().contains(appMetadataConfig.getClaims().getAudience())) {
                return null;
            }

            // Validate issuance time (should be recent)
            Date issuedAt = claims.getIssueTime();
            if (issuedAt == null || issuedAt.toInstant().isBefore(
                    Instant.now().minus(MAX_PROOF_AGE_SECONDS, ChronoUnit.SECONDS))) {
                return null;
            }

            // Validate nonce to prevent replay attacks
            String nonce = claims.getStringClaim("nonce");
            if (nonce != null && !isValidNonce(nonce)) {
                return null;
            }

            // 3. Extract Wallet Public Key from JWK Header
            JWK walletJwk = header.getJWK();
            if (walletJwk == null) {
                return null;
            }

            // 4. Verify Signature using the extracted wallet key
            boolean isValid = verifySignatureWithProvidedJwk(signedJWT, walletJwk);
            return isValid ? walletJwk : null;

        } catch (Exception e) {
            e.printStackTrace();
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
