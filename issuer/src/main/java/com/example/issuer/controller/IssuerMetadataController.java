package com.example.issuer.controller;

import com.example.issuer.config.AppMetadataConfig;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/.well-known")
public class IssuerMetadataController {

    private static final String CREDENTIAL_CONFIG_ID = "eu.europa.ec.eudi.pda1_sd_jwt_vc";

    private final AppMetadataConfig appMetadataConfig;

    public IssuerMetadataController(AppMetadataConfig appMetadataConfig) {
        this.appMetadataConfig = appMetadataConfig;
    }

    @GetMapping("/openid-credential-issuer")
    public ResponseEntity<Map<String, Object>> getMetadata() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("credential_issuer", appMetadataConfig.getEndpoints().getIssuer());
        metadata.put("authorization_servers", List.of(appMetadataConfig.getEndpoints().getAuthorization()));
        metadata.put("credential_endpoint", appMetadataConfig.getEndpoints().getCredential());
        metadata.put("nonce_endpoint", appMetadataConfig.getEndpoints().getCredential() + "/nonce");
        metadata.put("credential_configurations_supported", Map.of(
                CREDENTIAL_CONFIG_ID, buildCredentialConfiguration()
        ));

        return ResponseEntity.ok(metadata);
    }

    private Map<String, Object> buildCredentialConfiguration() {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("format", "dc+sd-jwt");
        config.put("vct", appMetadataConfig.getClaims().getVct());
        config.put("scope", CREDENTIAL_CONFIG_ID);
        config.put("cryptographic_binding_methods_supported", List.of("jwk"));
        config.put("credential_signing_alg_values_supported", List.of("ES256"));
        config.put("proof_types_supported", Map.of(
                "jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256"))
        ));
        config.put("display", List.of(Map.of(
                "name", "Portable Document A1",
                "locale", "en"
        )));
        config.put("claims", buildClaimsMetadata());
        return config;
    }

    private List<Map<String, Object>> buildClaimsMetadata() {
        return List.of(
                // credential_holder nested claims
                buildClaimMetadata(List.of("credential_holder", "family_name"), "Family Name", true),
                buildClaimMetadata(List.of("credential_holder", "given_name"), "Given Name", true),
                buildClaimMetadata(List.of("credential_holder", "birth_date"), "Birth Date", false),
                // competent_institution nested claims
                buildClaimMetadata(List.of("competent_institution", "country_code"), "Country Code", true),
                buildClaimMetadata(List.of("competent_institution", "institution_id"), "Institution ID", false),
                buildClaimMetadata(List.of("competent_institution", "institution_name"), "Institution Name", true)
        );
    }

    private Map<String, Object> buildClaimMetadata(List<String> path, String displayName, boolean mandatory) {
        return Map.of(
                "path", path,
                "display", List.of(Map.of("name", displayName, "locale", "en")),
                "mandatory", mandatory
        );
    }

}

