package com.example.issuer.model;

import java.time.Instant;

public record CredentialStatusEntry(
        String credentialId,
        String username,
        String status,
        String statusListId,
        int statusListIdx,
        Instant issuedAt
) {
}
