package com.example.issuer.controller;

import com.example.issuer.model.CredentialFormat;
import com.example.issuer.model.CredentialRequest;
import com.example.issuer.service.CredentialIssuerService;
import com.nimbusds.jose.jwk.JWK;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
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
     * Endpoint to get a nonce for credential issuance (OID4VCI 1.0 Final: POST, returns c_nonce).
     * Cache-Control: no-store is required per OID4VCI 1.0 Final section 7.2.
     */
    @PostMapping("/nonce")
    public ResponseEntity<Map<String, Object>> getNonce() {
        String nonce = credentialIssuerService.generateCredentialNonce();
        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, CacheControl.noStore().getHeaderValue())
                .body(Map.of(
                        "c_nonce", nonce,
                        "c_nonce_expires_in", 300 // 5 minutes
                ));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('SCOPE_eu.europa.ec.eudi.pda1.1')")
    public ResponseEntity<Map<String, Object>> issueCredential(@RequestBody CredentialRequest request,
                                                               Authentication authentication) throws Exception {

        // Validate proof and extract the wallet JWK
        JWK walletKey = credentialIssuerService.validateCredentialRequest(request);

        if (walletKey == null) {
            return ResponseEntity.badRequest()
                    .header(HttpHeaders.CACHE_CONTROL, CacheControl.noStore().getHeaderValue())
                    .body(Map.of(
                            "error", "invalid_proof",
                            "error_description", "The proof JWT did not pass validation"
                    ));
        }

        // Extract username
        String username = authentication.getName();

        // Determine format (defaults to dc+sd-jwt)
        CredentialFormat format = CredentialFormat.fromValue(request.format());

        // Issue credential and build response
        String credential = credentialIssuerService.issueCredential(format, walletKey, username);

        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, CacheControl.noStore().getHeaderValue())
                .body(Map.of(
                        "credential", credential
                ));
    }

}

