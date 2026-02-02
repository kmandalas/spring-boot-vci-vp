package com.example.walletprovider.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Request model for Wallet Instance Attestation (WIA) issuance.
 * Per draft-ietf-oauth-attestation-based-client-auth.
 *
 * @param clientId the OAuth client_id for which the WIA is requested
 * @param proof proof of possession of the wallet's ephemeral key
 */
public record WiaCredentialRequest(
        @JsonProperty("client_id") String clientId,
        Proof proof
) {
    public record Proof(
            @JsonProperty("proof_type") String proofType,
            String jwt
    ) {}
}
