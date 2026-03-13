package dev.kmandalas.verifier.service;

import dev.kmandalas.verifier.client.TrustValidatorClient;
import dev.kmandalas.verifier.config.AppConfig;
import dev.kmandalas.verifier.model.CredentialFormat;
import dev.kmandalas.verifier.model.PresentationRequest;
import dev.kmandalas.verifier.service.credential.MDocVerificationContext;
import dev.kmandalas.verifier.service.credential.MDocVerifierService;
import dev.kmandalas.verifier.service.credential.SdJwtVerifierService;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Orchestration service for VP (Verifiable Presentation) validation.
 * Detects credential format and delegates to format-specific verifier services.
 */
@Service
public class VpValidationService {

    private static final Logger logger = LoggerFactory.getLogger(VpValidationService.class);

    private final AppConfig appConfig;
    private final TrustValidatorClient trustValidatorClient;
    private final StatusListTokenValidator statusListTokenValidator;
    private final SdJwtVerifierService sdJwtVerifierService;
    private final MDocVerifierService mDocVerifierService;

    public VpValidationService(AppConfig appConfig,
                               TrustValidatorClient trustValidatorClient,
                               StatusListTokenValidator statusListTokenValidator,
                               SdJwtVerifierService sdJwtVerifierService,
                               MDocVerifierService mDocVerifierService) {
        this.appConfig = appConfig;
        this.trustValidatorClient = trustValidatorClient;
        this.statusListTokenValidator = statusListTokenValidator;
        this.sdJwtVerifierService = sdJwtVerifierService;
        this.mDocVerifierService = mDocVerifierService;
    }

    /**
     * Result of VP validation containing status and disclosed claims.
     */
    public record ValidationResult(boolean valid, String issuer, Map<String, Object> disclosedClaims, String error) {
        public static ValidationResult success(String issuer, Map<String, Object> claims) {
            return new ValidationResult(true, issuer, claims, null);
        }

        public static ValidationResult failure(String error) {
            return new ValidationResult(false, null, Map.of(), error);
        }
    }

    /**
     * Validates a VP token and extracts disclosed claims with format validation and DeviceAuth.
     * Uses expected format from DCQL query if provided, otherwise auto-detects.
     * Creates MDocVerificationContext only when format is mDoc.
     *
     * @param vpToken the VP token (SD-JWT or base64url-encoded mDoc)
     * @param request PresentationRequest containing expected format and DeviceAuth parameters (may be null)
     * @return ValidationResult with status and claims
     */
    public ValidationResult validateAndExtract(String vpToken, PresentationRequest request) {
        CredentialFormat expectedFormat = request != null ? request.expectedFormat() : null;

        // Determine format: use expected format if provided, otherwise auto-detect
        boolean isMDoc;
        if (expectedFormat != null) {
            isMDoc = expectedFormat == CredentialFormat.MSO_MDOC;
            logger.debug("Using expected format from DCQL: {}", expectedFormat.value());

            // Validate that token structure matches expected format
            boolean tokenLooksMDoc = isMDocFormat(vpToken);
            if (isMDoc != tokenLooksMDoc) {
                return ValidationResult.failure(
                        "Format mismatch: expected " + expectedFormat.value() +
                                " but token " + (tokenLooksMDoc ? "appears to be mDoc" : "appears to be SD-JWT"));
            }
        } else {
            // Fallback to auto-detection
            isMDoc = isMDocFormat(vpToken);
            logger.debug("Auto-detected format: {}", isMDoc ? CredentialFormat.MSO_MDOC.value() : CredentialFormat.DC_SD_JWT.value());
        }

        if (isMDoc) {
            // Create MDocVerificationContext only for mDoc format
            MDocVerificationContext context = null;
            if (request != null) {
                context = new MDocVerificationContext(
                        request.clientId(),
                        request.responseUri(),
                        request.nonce(),
                        request.ephemeralKeyThumbprint()
                );
            }
            return validateMDoc(vpToken, context);
        } else {
            return validateSdJwt(vpToken);
        }
    }

    /**
     * Validates an SD-JWT VP token.
     */
    private ValidationResult validateSdJwt(String vpToken) {
        try {
            // Step 1: Extract issuer and validate against trusted list (or trust-validator)
            String issuer = sdJwtVerifierService.extractIssuer(vpToken);
            if (appConfig.getTrustValidator().isEnabled()) {
                List<Base64> x5cChain = sdJwtVerifierService.extractX5cChain(vpToken);
                if (x5cChain == null || x5cChain.isEmpty()) {
                    logger.warn("Credential has no x5c chain, required when trust-validator is enabled");
                    return ValidationResult.failure("Credential x5c chain missing");
                }
                JWTClaimsSet credClaims = sdJwtVerifierService.getCredentialClaims(vpToken);
                String vct = credClaims.getStringClaim("vct");
                String context = appConfig.getTrustValidator().getVctToContext()
                        .getOrDefault(vct, appConfig.getTrustValidator().getDefaultContext());
                Optional<String> trustAnchor = trustValidatorClient.isTrusted(
                        x5cChain, context, appConfig.getTrustValidator().getUrl());
                if (trustAnchor.isEmpty()) {
                    logger.warn("Credential chain not trusted by trust-validator (issuer={}, vct={})", issuer, vct);
                    return ValidationResult.failure("Credential chain not trusted by trust-validator");
                }
                logger.info("Credential chain validated by trust-validator (anchor='{}')",
                        certSubject(java.util.Base64.getDecoder().decode(trustAnchor.get())));
            } else {
                if (!appConfig.isTrustedIssuer(issuer)) {
                    logger.warn("Untrusted credential issuer: {}", issuer);
                    return ValidationResult.failure("Untrusted credential issuer: " + issuer);
                }
                logger.info("Credential issuer '{}' is trusted", issuer);
            }

            // Step 2: Fetch JWKS key for x5c cross-check (skipped when trust-validator already validated the chain)
            JWK jwksKey = null;
            if (!appConfig.getTrustValidator().isEnabled()) {
                String jwksUrl = issuer + "/.well-known/jwks.json";
                logger.debug("Fetching issuer JWKS from: {}", jwksUrl);
                jwksKey = JWKSet.load(URI.create(jwksUrl).toURL()).getKeys().getFirst();
                logger.info("Loaded issuer public key from JWKS");
            }

            // Step 3: Verify SD-JWT — signing key extracted from x5c internally; JWKS key used for cross-check if provided
            SdJwtVerifierService.SdJwtValidationResult result =
                    sdJwtVerifierService.verifySdJwtPresentation(vpToken, jwksKey);

            if (!result.valid()) {
                return ValidationResult.failure(result.error());
            }
            logger.info("SD-JWT VP signature verification successful");

            // Step 4: Check credential revocation status (Token Status List)
            if (appConfig.isStatusCheckEnabled()) {
                JWTClaimsSet credentialClaims = sdJwtVerifierService.getCredentialClaims(vpToken);
                StatusListTokenValidator.StatusCheckResult statusResult =
                        statusListTokenValidator.checkStatus(credentialClaims);
                switch (statusResult) {
                    case StatusListTokenValidator.StatusCheckResult.Revoked() -> {
                        return ValidationResult.failure("Credential has been revoked");
                    }
                    case StatusListTokenValidator.StatusCheckResult.Error(String msg) -> {
                        return ValidationResult.failure("Status check failed: " + msg);
                    }
                    case StatusListTokenValidator.StatusCheckResult.Valid() ->
                            logger.info("Credential status check passed");
                    case StatusListTokenValidator.StatusCheckResult.Skipped() ->
                            logger.debug("No status claim in credential - skipping status check");
                }
            }

            return ValidationResult.success(issuer, result.disclosedClaims());

        } catch (Exception e) {
            logger.error("SD-JWT VP validation failed", e);
            return ValidationResult.failure(e.getMessage());
        }
    }

    /**
     * Validates an mDoc VP token with optional DeviceAuth verification.
     *
     * @param vpToken the base64url-encoded mDoc DeviceResponse
     * @param context DeviceAuth context (null to skip DeviceAuth verification)
     */
    private ValidationResult validateMDoc(String vpToken, MDocVerificationContext context) {
        try {
            // Verify mDoc: key is extracted from IssuerAuth x5chain internally (ISO 18013-5)
            MDocVerifierService.MDocValidationResult mDocResult =
                    mDocVerifierService.verifyMDocPresentation(vpToken, context);

            if (!mDocResult.valid()) {
                return ValidationResult.failure("mDoc validation failed: " + mDocResult.error());
            }

            // Trust validation using x5chain from the verified result
            String issuer;
            if (appConfig.getTrustValidator().isEnabled()) {
                List<Base64> x5cChain = mDocResult.x5cChain();
                if (x5cChain == null || x5cChain.isEmpty()) {
                    return ValidationResult.failure("mDoc IssuerAuth has no x5chain");
                }
                String tvContext = appConfig.getTrustValidator().getDefaultContext();
                Optional<String> trustAnchor = trustValidatorClient.isTrusted(
                        x5cChain, tvContext, appConfig.getTrustValidator().getUrl());
                if (trustAnchor.isEmpty()) {
                    return ValidationResult.failure("mDoc chain not trusted by trust-validator");
                }
                logger.info("mDoc chain validated by trust-validator (context={}, anchor='{}')",
                        tvContext, certSubject(java.util.Base64.getDecoder().decode(trustAnchor.get())));
                issuer = certSubject(x5cChain.getFirst().decode()); // leaf cert CN as issuer identity
            } else {
                if (appConfig.getTrustedIssuers().isEmpty()) {
                    return ValidationResult.failure("No trusted issuers configured for mDoc validation");
                }
                issuer = appConfig.getTrustedIssuers().getFirst();
            }

            logger.info("mDoc VP verified - issuer='{}'", issuer);
            return ValidationResult.success(issuer, mDocResult.disclosedClaims());

        } catch (Exception e) {
            logger.error("mDoc VP validation failed", e);
            return ValidationResult.failure(e.getMessage());
        }
    }

    /** Returns the Subject DN of a DER-encoded X.509 certificate, or a truncated fallback on error. */
    private String certSubject(byte[] derBytes) {
        try {
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(derBytes));
            return cert.getSubjectX500Principal().getName();
        } catch (Exception e) {
            return "(unparseable cert)";
        }
    }

    /**
     * Detects if the VP token is in mDoc format.
     * mDoc is base64url-encoded CBOR (no dots), while SD-JWT has dots.
     */
    private boolean isMDocFormat(String vpToken) {
        return vpToken != null && !vpToken.contains(".");
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
                    if (!vpList.isEmpty() && vpList.getFirst() instanceof String) {
                        return (String) vpList.getFirst();
                    }
                }
            }
        }

        return null;
    }

}
