package com.example.issuer.controller;

import com.example.issuer.config.AppMetadataConfig;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/.well-known")
public class IssuerMetadataController {

    private final AppMetadataConfig appMetadataConfig;

    public IssuerMetadataController(AppMetadataConfig appMetadataConfig) {
        this.appMetadataConfig = appMetadataConfig;
    }

    @GetMapping("/openid-credential-issuer")
    public ResponseEntity<Map<String, Object>> getMetadata() {
        Map<String, Object> metadata = Map.of(
                "credential_issuer", appMetadataConfig.getEndpoints().getIssuer(),
                "authorization_server", appMetadataConfig.getEndpoints().getAuthorization(),
                "credential_endpoint", appMetadataConfig.getEndpoints().getCredential(),
                "credential_configurations_supported", Map.of(
                        "VerifiablePortableDocumentA1", Map.of(
                                "format", "vc+sd-jwt",
                                "scope", "VerifiablePortableDocumentA1",
                                "proof_types_supported", List.of("jwt")
                        )
                )
        );

        return ResponseEntity.ok(metadata);
    }

}

