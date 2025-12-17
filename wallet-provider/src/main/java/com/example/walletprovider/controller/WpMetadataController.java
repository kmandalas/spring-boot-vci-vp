package com.example.walletprovider.controller;

import com.example.walletprovider.config.WpMetadataConfig;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

@RestController
@RequestMapping("/.well-known")
public class WpMetadataController {

    private final WpMetadataConfig wpMetadataConfig;

    public WpMetadataController(WpMetadataConfig wpMetadataConfig) {
        this.wpMetadataConfig = wpMetadataConfig;
    }

    @GetMapping(value = "/openid-credential-issuer", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getMetadata() {
        Map<String, Object> metadata = new LinkedHashMap<>();

        metadata.put("credential_issuer", wpMetadataConfig.getEndpoints().getIssuer());
        metadata.put("credential_endpoint", wpMetadataConfig.getEndpoints().getCredential());

        // Credential configurations supported
        Map<String, Object> wuaConfig = new LinkedHashMap<>();
        wuaConfig.put("format", "jwt");
        wuaConfig.put("scope", "WalletUnitAttestation");

        Map<String, Object> proofTypes = new LinkedHashMap<>();
        proofTypes.put("jwt", Map.of(
                "proof_signing_alg_values_supported", List.of("ES256", "ES384", "RS256")
        ));
        wuaConfig.put("proof_types_supported", proofTypes);

        wuaConfig.put("credential_definition", Map.of(
                "type", List.of("WalletUnitAttestation")
        ));

        Map<String, Object> credentialConfigs = new LinkedHashMap<>();
        credentialConfigs.put("WalletUnitAttestation", wuaConfig);

        metadata.put("credential_configurations_supported", credentialConfigs);

        return ResponseEntity.ok(metadata);
    }
}
