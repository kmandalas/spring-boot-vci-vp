package dev.kmandalas.qtspmock.controller;

import dev.kmandalas.qtspmock.model.*;
import dev.kmandalas.qtspmock.service.KeyManagementService;
import dev.kmandalas.qtspmock.service.KeyManagementService.ManagedCredential;
import dev.kmandalas.qtspmock.service.SadService;
import dev.kmandalas.qtspmock.service.SigningService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/csc/v2")
public class CscController {

    private static final Logger logger = LoggerFactory.getLogger(CscController.class);

    private final KeyManagementService keyManagementService;
    private final SadService sadService;
    private final SigningService signingService;

    public CscController(KeyManagementService keyManagementService, SadService sadService,
                          SigningService signingService) {
        this.keyManagementService = keyManagementService;
        this.sadService = sadService;
        this.signingService = signingService;
    }

    @GetMapping(value = "/info", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getInfo() {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("specs", "2.0.0.0");
        info.put("name", "K-QTSP Mock");
        info.put("logo", "");
        info.put("region", "GR");
        info.put("lang", "en-US");
        info.put("description", "Mock QTSP implementing CSC API v2 for EUDI Wallet RQSCD demo");
        info.put("authType", List.of("external"));
        info.put("methods", List.of(
                "credentials/list",
                "credentials/info",
                "credentials/authorize",
                "signatures/signHash"
        ));

        logger.info("📋 CSC info requested");
        return ResponseEntity.ok(info);
    }

    @PostMapping(value = "/credentials/list",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CredentialsListResponse> listCredentials(@RequestBody(required = false) CredentialsListRequest request) {
        String userId = (request != null) ? request.userId() : null;
        List<String> credentialIds = keyManagementService.listCredentialIds(userId);
        logger.info("📋 Listed {} credentials for user '{}'", credentialIds.size(), userId);
        return ResponseEntity.ok(new CredentialsListResponse(credentialIds));
    }

    @PostMapping(value = "/credentials/info",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getCredentialInfo(@RequestBody CredentialInfoRequest request) {
        if (request.credentialId() == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_request",
                    "error_description", "credentialID is required"
            ));
        }

        ManagedCredential credential = keyManagementService.getCredential(request.credentialId());
        if (credential == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_credential",
                    "error_description", "Credential not found: " + request.credentialId()
            ));
        }

        List<String> certChain = keyManagementService.getCertificateChainBase64(credential);

        var keyInfo = new CredentialInfoResponse.KeyInfo(
                "enabled",
                List.of("1.2.840.10045.4.3.2"), // SHA256withECDSA OID
                256,
                "P-256"
        );

        var certInfo = new CredentialInfoResponse.CertInfo(
                "valid",
                certChain, // [user cert, CA cert]
                credential.userCertificate().getIssuerX500Principal().getName(),
                credential.userCertificate().getSubjectX500Principal().getName()
        );

        var authInfo = new CredentialInfoResponse.AuthInfo(
                "explicit",
                List.of("PIN")
        );

        var response = new CredentialInfoResponse(
                "EUDI Wallet signing credential",
                keyInfo,
                certInfo,
                authInfo,
                "2" // SCAL 2 = key is in hardware (QSCD)
        );

        logger.info("🔍 Credential info for: {}", request.credentialId());
        return ResponseEntity.ok(response);
    }

    @PostMapping(value = "/credentials/authorize",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> authorizeCredential(@RequestBody CredentialAuthorizeRequest request) {
        if (request.credentialId() == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_request",
                    "error_description", "credentialID is required"
            ));
        }

        ManagedCredential credential = keyManagementService.getCredential(request.credentialId());
        if (credential == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_credential",
                    "error_description", "Credential not found: " + request.credentialId()
            ));
        }

        String sad = sadService.issueSad(request.credentialId());
        long expiresIn = sadService.getTtlSeconds();

        logger.info("🔐 Authorized credential: {}", request.credentialId());
        return ResponseEntity.ok(new CredentialAuthorizeResponse(sad, expiresIn));
    }

    @PostMapping(value = "/signatures/signHash",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> signHash(@RequestBody SignHashRequest request) {
        if (request.credentialId() == null || request.sad() == null || request.hash() == null || request.hash().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_request",
                    "error_description", "credentialID, SAD, and hash are required"
            ));
        }

        // Validate and consume SAD (single-use)
        String validatedCredentialId = sadService.validateAndConsume(request.sad(), request.credentialId());
        if (validatedCredentialId == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_sad",
                    "error_description", "SAD is invalid, expired, or already used"
            ));
        }

        ManagedCredential credential = keyManagementService.getCredential(request.credentialId());
        if (credential == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_credential",
                    "error_description", "Credential not found"
            ));
        }

        // Sign each hash
        List<String> signatures = new ArrayList<>();
        for (String hashBase64 : request.hash()) {
            byte[] hash = Base64.getDecoder().decode(hashBase64);
            String signature = signingService.signHash(credential.privateKey(), hash);
            signatures.add(signature);
        }

        logger.info("✍️ Signed {} hash(es) for credential: {}", signatures.size(), request.credentialId());
        return ResponseEntity.ok(new SignHashResponse(signatures));
    }

}
