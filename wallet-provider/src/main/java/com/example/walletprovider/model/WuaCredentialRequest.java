package com.example.walletprovider.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record WuaCredentialRequest(
        Proof proof,
        @JsonProperty("key_attestation") KeyAttestation keyAttestation
) {
    public record Proof(
            @JsonProperty("proof_type") String proofType,
            String jwt
    ) {}

    public record KeyAttestation(
            @JsonProperty("attestation_type") String attestationType,
            @JsonProperty("certificate_chain") List<String> certificateChain
    ) {}
}
