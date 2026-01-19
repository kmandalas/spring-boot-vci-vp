package com.example.walletprovider.service;

import com.example.walletprovider.config.WpMetadataConfig;
import com.example.walletprovider.model.KeyAttestationData;
import com.example.walletprovider.model.WalletUnitAttestation;
import com.example.walletprovider.model.WuaCredentialRequest;
import com.example.walletprovider.repository.WuaRepository;
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

import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class WuaIssuerService {

    private static final Logger logger = LoggerFactory.getLogger(WuaIssuerService.class);

    private final Set<String> usedNonces = ConcurrentHashMap.newKeySet();

    private final WpMetadataConfig wpMetadataConfig;
    private final WuaRepository wuaRepository;
    private final KeyAttestationService keyAttestationService;
    private final WpSigningService wpSigningService;
    private final StatusListIndexService statusListIndexService;

    public WuaIssuerService(WpMetadataConfig wpMetadataConfig, WuaRepository wuaRepository,
                           KeyAttestationService keyAttestationService, WpSigningService wpSigningService,
                           StatusListIndexService statusListIndexService) {
        this.wpMetadataConfig = wpMetadataConfig;
        this.wuaRepository = wuaRepository;
        this.keyAttestationService = keyAttestationService;
        this.wpSigningService = wpSigningService;
        this.statusListIndexService = statusListIndexService;
    }

    public String generateNonce() {
        return UUID.randomUUID().toString();
    }

    public JWK validateCredentialRequest(WuaCredentialRequest request) {
        if (request == null || request.proof() == null || request.proof().jwt() == null) {
            logger.warn("⚠️Invalid request: missing proof or JWT");
            return null;
        }

        if (!"jwt".equals(request.proof().proofType())) {
            logger.warn("⚠️Invalid proof type: {}", request.proof().proofType());
            return null;
        }

        return validateProof(request.proof().jwt());
    }

    public KeyAttestationData validateKeyAttestation(WuaCredentialRequest request, JWK proofJwk)
            throws CertificateException, CertPathValidatorException {

        if (request.keyAttestation() == null) {
            throw new CertificateException("Key attestation is required");
        }

        if (!"android_key_attestation".equals(request.keyAttestation().attestationType())) {
            throw new CertificateException("Unsupported attestation type: " +
                    request.keyAttestation().attestationType());
        }

        KeyAttestationData attestationData = keyAttestationService.validateAndExtract(
                request.keyAttestation().certificateChain());

        // Verify that the public key in the attestation matches the proof JWT's JWK
        verifyKeyMatch(proofJwk, attestationData.walletPublicKey());

        return attestationData;
    }

    public WuaIssuanceResult issueWua(JWK walletKey, KeyAttestationData attestationData)
            throws JOSEException {

        UUID wuaId = UUID.randomUUID();
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(wpMetadataConfig.getTime().getWuaTtlSeconds(), ChronoUnit.SECONDS);

        // Allocate status list index (per IETF Token Status List spec)
        var statusList = statusListIndexService.getOrCreateActiveList();
        int statusListIdx = statusListIndexService.allocateIndex(statusList.id());

        // Generate WUA JWT with status list reference
        String wuaJwt = generateWuaJwt(wuaId, walletKey, attestationData, issuedAt, expiresAt,
                statusList.id(), statusListIdx);

        // Persist WUA record with status list fields
        String thumbprint = walletKey.computeThumbprint().toString();
        WalletUnitAttestation wua = new WalletUnitAttestation(
                wuaId,
                thumbprint,
                attestationData.wscdType(),
                attestationData.wscdSecurityLevel(),
                issuedAt,
                expiresAt,
                statusList.id(),
                statusListIdx
        );
        wuaRepository.save(wua);

        logger.info("Issued WUA: id={}, wscdType={}, statusListIdx={}, expires={}",
                wuaId, attestationData.wscdType(), statusListIdx, expiresAt);

        return new WuaIssuanceResult(wuaJwt, wuaId);
    }

    private String generateWuaJwt(UUID wuaId, JWK walletKey, KeyAttestationData attestationData,
                                   Instant issuedAt, Instant expiresAt,
                                   String statusListId, int statusListIdx)
            throws JOSEException {

        ECKey wpKey = wpSigningService.getSigningKey();

        // Build header with x5c certificate chain (TS3: typ = "key-attestation+jwt")
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(wpKey.getKeyID())
                .type(new JOSEObjectType("key-attestation+jwt"))
                .x509CertChain(wpSigningService.getX5cChain())
                .build();

        // Build attested_keys array (TS3 Section 2.3.4)
        Map<String, Object> attestedKey = new LinkedHashMap<>();
        attestedKey.put("kty", walletKey.getKeyType().getValue());
        if (walletKey instanceof ECKey ecKey) {
            attestedKey.put("crv", ecKey.getCurve().getName());
            attestedKey.put("x", ecKey.getX().toString());
            attestedKey.put("y", ecKey.getY().toString());
            attestedKey.put("alg", "ES256");
            // Include kid if present (needed for KB-JWT verification)
            if (walletKey.getKeyID() != null) {
                attestedKey.put("kid", walletKey.getKeyID());
            }
        }

        // TS3 Section 2.3.1: general_info
        Map<String, Object> generalInfo = new LinkedHashMap<>();
        generalInfo.put("wallet_provider_name", wpMetadataConfig.getProvider().getName());
        generalInfo.put("wallet_solution_id", wpMetadataConfig.getProvider().getId());
        generalInfo.put("wallet_solution_version", wpMetadataConfig.getProvider().getSolutionVersion());
        generalInfo.put("wallet_solution_certification_information", wpMetadataConfig.getProvider().getCertificationInformation());

        // TS3 Section 2.3.2: wscd_info (was key_storage_info)
        Map<String, Object> wscdCertInfo = new LinkedHashMap<>();
        wscdCertInfo.put("wscd_type", attestationData.wscdType());
        wscdCertInfo.put("security_level", attestationData.wscdSecurityLevel());
        wscdCertInfo.put("attestation_version", attestationData.attestationVersion());

        Map<String, Object> wscdInfo = new LinkedHashMap<>();
        wscdInfo.put("wscd_type", "LOCAL_NATIVE");  // TS3: REMOTE, LOCAL_EXTERNAL, LOCAL_INTERNAL, LOCAL_NATIVE, HYBRID
        wscdInfo.put("wscd_certification_information", wscdCertInfo);

        // TS3 Section 2.3.4: eudi_wallet_info
        Map<String, Object> eudiWalletInfo = new LinkedHashMap<>();
        eudiWalletInfo.put("general_info", generalInfo);
        eudiWalletInfo.put("wscd_info", wscdInfo);

        // Token Status List reference per IETF draft-ietf-oauth-status-list
        Map<String, Object> statusListClaim = new LinkedHashMap<>();
        statusListClaim.put("idx", statusListIdx);
        statusListClaim.put("uri", wpMetadataConfig.getEndpoints().getStatusList() + "/" + statusListId);

        Map<String, Object> status = new LinkedHashMap<>();
        status.put("status_list", statusListClaim);

        // TS3 Section 2.3: Map WSCD type to ISO 18045 attack potential resistance
        String keyStorageResistance = mapWscdToIso18045(attestationData.wscdType());

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(wpMetadataConfig.getClaims().getIss())
                .subject(wpMetadataConfig.getProvider().getClientId())  // TS3: sub = client_id
                .jwtID(wuaId.toString())  // RFC 7519: jti = unique JWT identifier
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiresAt))
                .claim("attested_keys", List.of(attestedKey))
                .claim("key_storage", List.of(keyStorageResistance))  // OID4VCI: top-level key_storage
                .claim("user_authentication", List.of(keyStorageResistance))  // OID4VCI: top-level user_authentication
                .claim("eudi_wallet_info", eudiWalletInfo)
                .claim("status", status)
                .build();

        // Sign JWT
        SignedJWT signedJWT = new SignedJWT(header, claims);
        JWSSigner signer = new ECDSASigner(wpKey);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    /**
     * Maps Android WSCD type to ISO 18045 attack potential resistance level.
     * Per TS3 Section 2.3: key_storage indicates attack potential resistance.
     */
    private String mapWscdToIso18045(String wscdType) {
        if (wscdType == null) {
            return "iso_18045_basic";
        }
        return switch (wscdType.toLowerCase()) {
            case "strongbox" -> "iso_18045_high";
            case "tee" -> "iso_18045_high";  // TEE also qualifies as high for WSCD
            case "software" -> "iso_18045_basic";
            default -> "iso_18045_basic";
        };
    }

    private JWK validateProof(String proofJwt) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(proofJwt);

            JWSHeader header = signedJWT.getHeader();

            // Reject 'none' and symmetric algorithms
            JWSAlgorithm algorithm = header.getAlgorithm();
            if (algorithm == JWSAlgorithm.NONE || algorithm.getName().startsWith("HS")) {
                logger.warn("⚠️Rejected algorithm: {}", algorithm);
                return null;
            }

            // Verify type
            if (header.getType() == null || !"openid4vci-proof+jwt".equals(header.getType().toString())) {
                logger.warn("⚠️Invalid proof type header: {}", header.getType());
                return null;
            }

            // Either kid or jwk, not both
            if (header.getKeyID() != null && header.getJWK() != null) {
                logger.warn("⚠️Both kid and jwk present in header");
                return null;
            }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            // Validate audience
            if (!claims.getAudience().contains(wpMetadataConfig.getClaims().getAudience())) {
                logger.warn("⚠️Invalid audience: {}", claims.getAudience());
                return null;
            }

            // Validate issuance time
            Date issuedAt = claims.getIssueTime();
            long maxProofAge = wpMetadataConfig.getTime().getMaxProofAgeSeconds();
            if (issuedAt == null || issuedAt.toInstant().isBefore(
                    Instant.now().minus(maxProofAge, ChronoUnit.SECONDS))) {
                logger.warn("⚠️Proof JWT too old or missing iat");
                return null;
            }

            // Validate nonce
            String nonce = claims.getStringClaim("nonce");
            if (nonce != null && !isValidNonce(nonce)) {
                logger.warn("⚠️Invalid or reused nonce");
                return null;
            }

            // Extract wallet public key
            JWK walletJwk = header.getJWK();
            if (walletJwk == null) {
                logger.warn("⚠️Missing JWK in proof header");
                return null;
            }

            // Verify signature
            if (!verifySignatureWithProvidedJwk(signedJWT, walletJwk)) {
                logger.warn("⚠️Proof signature verification failed");
                return null;
            }

            return walletJwk;

        } catch (Exception e) {
            logger.error("❌Error validating proof JWT", e);
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
            logger.error("❌Error verifying signature", e);
            return false;
        }
    }

    private void verifyKeyMatch(JWK proofJwk, java.security.PublicKey attestedKey)
            throws CertificateException {
        try {
            if (proofJwk.getKeyType() == KeyType.EC) {
                ECPublicKey proofKey = ((ECKey) proofJwk).toECPublicKey();
                if (attestedKey instanceof ECPublicKey attestedEcKey) {
                    if (!proofKey.getW().equals(attestedEcKey.getW())) {
                        throw new CertificateException("Proof key does not match attested key");
                    }
                } else {
                    throw new CertificateException("Key type mismatch: proof is EC but attested is not");
                }
            } else {
                throw new CertificateException("Unsupported key type: " + proofJwk.getKeyType());
            }
        } catch (JOSEException e) {
            throw new CertificateException("Error comparing keys", e);
        }
    }

    public record WuaIssuanceResult(String wuaJwt, UUID wuaId) {}

}
