package com.example.issuer.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

public record CredentialRequest(
        String format,
        @JsonProperty("credential_configuration_id") String credentialConfigurationId,
        Proof proof,
        Map<String, List<String>> proofs
) {
    public record Proof(
            @JsonProperty("proof_type") String proofType,
            String jwt
    ) {}
}
