package com.example.issuer.model;

public record CredentialRequest(
        String format,
        String credentialConfigurationId,
        Proof proof
) {
    public record Proof(String proofType, String jwt) {}
}
