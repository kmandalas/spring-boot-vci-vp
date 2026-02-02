package com.example.walletprovider.controller;

import com.example.walletprovider.config.WpMetadataConfig;
import com.example.walletprovider.model.KeyAttestationData;
import com.example.walletprovider.model.WuaCredentialRequest;
import com.example.walletprovider.service.WuaIssuerService;
import com.nimbusds.jose.jwk.JWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/wp/wua")
public class WuaCredentialController {

    private static final Logger logger = LoggerFactory.getLogger(WuaCredentialController.class);

    private final WuaIssuerService wuaIssuerService;
    private final WpMetadataConfig wpMetadataConfig;

    public WuaCredentialController(WuaIssuerService wuaIssuerService, WpMetadataConfig wpMetadataConfig) {
        this.wuaIssuerService = wuaIssuerService;
        this.wpMetadataConfig = wpMetadataConfig;
    }

    @GetMapping(value = "/nonce", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getNonce() {
        String nonce = wuaIssuerService.generateNonce();

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("c_nonce", nonce);
        response.put("c_nonce_expires_in", wpMetadataConfig.getTime().getNonceTtlSeconds());

        return ResponseEntity.ok(response);
    }

    @PostMapping(value = "/credential",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> issueWuaCredential(@RequestBody WuaCredentialRequest request) {
        try {
            // 1. Validate proof JWT
            JWK walletKey = wuaIssuerService.validateCredentialRequest(request);
            if (walletKey == null) {
                logger.warn("⚠️Proof validation failed");
                return ResponseEntity.badRequest().body(Map.of(
                        "error", "invalid_proof",
                        "error_description", "The provided proof JWT is invalid"
                ));
            }

            // 2. Validate key attestation
            KeyAttestationData attestationData;
            try {
                attestationData = wuaIssuerService.validateKeyAttestation(request, walletKey);
            } catch (CertificateException | CertPathValidatorException e) {
                logger.warn("⚠️Key attestation validation failed: {}", e.getMessage());
                return ResponseEntity.badRequest().body(Map.of(
                        "error", "invalid_key_attestation",
                        "error_description", e.getMessage()
                ));
            }

            // 3. Issue WUA
            WuaIssuerService.WuaIssuanceResult result = wuaIssuerService.issueWua(walletKey, attestationData);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("format", "jwt");
            response.put("credential", result.wuaJwt());
            response.put("wua_id", result.wuaId().toString());

            logger.info("Successfully issued WUA: {}", result.wuaId());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("❌Error issuing WUA", e);
            return ResponseEntity.internalServerError().body(Map.of(
                    "error", "server_error",
                    "error_description", "An error occurred while issuing the WUA"
            ));
        }
    }

}
