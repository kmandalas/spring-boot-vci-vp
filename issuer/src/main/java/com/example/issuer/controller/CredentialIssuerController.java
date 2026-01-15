package com.example.issuer.controller;

import com.example.issuer.model.CredentialRequest;
import com.example.issuer.service.CredentialIssuerService;
import com.nimbusds.jose.jwk.JWK;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/credential")
public class CredentialIssuerController {

    private final CredentialIssuerService credentialIssuerService;

    public CredentialIssuerController(CredentialIssuerService credentialIssuerService) {
        this.credentialIssuerService = credentialIssuerService;
    }

    /**
     * Endpoint to get a nonce for credential issuance
     */
    @GetMapping("/nonce")
    public ResponseEntity<Map<String, Object>> getNonce() {
        String nonce = credentialIssuerService.generateCredentialNonce();
        return ResponseEntity.ok(Map.of(
                "c_nonce", nonce,
                "c_nonce_expires_in", 300 // 5 minutes
        ));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('SCOPE_eu.europa.ec.eudi.pda1_sd_jwt_vc')")
    public ResponseEntity<Map<String, Object>> issueCredential(@RequestBody CredentialRequest request,
                                                               Authentication authentication) throws Exception {

        // Validate proof and extract the wallet JWK
        JWK walletKey = credentialIssuerService.validateCredentialRequest(request);

        if (walletKey == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_proof",
                    "error_description", "The proof JWT did not pass validation"
            ));
        }

        // Extract username
        String username = authentication.getName();

        // Generate SD-JWT VC using the wallet's JWK
        String sdJwt = credentialIssuerService.generateSdJwt(walletKey, username);

        // Prepare response according to the spec
        Map<String, Object> response = Map.of(
                "format", "dc+sd-jwt",
                "credential", sdJwt
        );

        return ResponseEntity.ok(response);
    }

}

