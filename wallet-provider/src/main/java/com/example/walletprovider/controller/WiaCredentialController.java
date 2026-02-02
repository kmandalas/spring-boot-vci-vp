package com.example.walletprovider.controller;

import com.example.walletprovider.config.WpMetadataConfig;
import com.example.walletprovider.model.WiaCredentialRequest;
import com.example.walletprovider.service.WiaIssuerService;
import com.nimbusds.jose.jwk.JWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Controller for Wallet Instance Attestation (WIA) issuance.
 * Per draft-ietf-oauth-attestation-based-client-auth.
 */
@RestController
@RequestMapping("/wp/wia")
public class WiaCredentialController {

    private static final Logger logger = LoggerFactory.getLogger(WiaCredentialController.class);

    private final WiaIssuerService wiaIssuerService;
    private final WpMetadataConfig wpMetadataConfig;

    public WiaCredentialController(WiaIssuerService wiaIssuerService, WpMetadataConfig wpMetadataConfig) {
        this.wiaIssuerService = wiaIssuerService;
        this.wpMetadataConfig = wpMetadataConfig;
    }

    /**
     * Get a nonce for WIA request proof.
     */
    @GetMapping(value = "/nonce", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getNonce() {
        String nonce = wiaIssuerService.generateNonce();

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("c_nonce", nonce);
        response.put("c_nonce_expires_in", wpMetadataConfig.getTime().getNonceTtlSeconds());

        return ResponseEntity.ok(response);
    }

    /**
     * Issue a Wallet Instance Attestation (WIA).
     * The wallet sends a proof JWT to demonstrate possession of its ephemeral key.
     * The WIA contains the wallet's public key in the cnf.jwk claim.
     */
    @PostMapping(value = "/credential",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> issueWiaCredential(@RequestBody WiaCredentialRequest request) {
        try {
            // 1. Validate proof JWT and extract wallet's public key
            JWK walletKey = wiaIssuerService.validateCredentialRequest(request);
            if (walletKey == null) {
                logger.warn("Proof validation failed");
                return ResponseEntity.badRequest().body(Map.of(
                        "error", "invalid_proof",
                        "error_description", "The provided proof JWT is invalid"
                ));
            }

            // 2. Issue WIA
            WiaIssuerService.WiaIssuanceResult result = wiaIssuerService.issueWia(walletKey, request.clientId());

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("format", "jwt");
            response.put("credential", result.wiaJwt());
            response.put("wia_id", result.wiaId().toString());

            logger.info("Successfully issued WIA: {}", result.wiaId());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Error issuing WIA", e);
            return ResponseEntity.internalServerError().body(Map.of(
                    "error", "server_error",
                    "error_description", "An error occurred while issuing the WIA"
            ));
        }
    }

}
