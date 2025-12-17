package com.example.walletprovider.model;

import java.time.Instant;
import java.util.UUID;

public record WalletUnitAttestation(
        UUID wuaId,
        String walletPublicKeyThumbprint,
        String status,
        String wscdType,
        String wscdSecurityLevel,
        Instant issuedAt,
        Instant expiresAt
) {
    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_REVOKED = "REVOKED";

    public WalletUnitAttestation(UUID wuaId, String walletPublicKeyThumbprint, String wscdType,
                                  String wscdSecurityLevel, Instant issuedAt, Instant expiresAt) {
        this(wuaId, walletPublicKeyThumbprint, STATUS_ACTIVE, wscdType, wscdSecurityLevel, issuedAt, expiresAt);
    }
}
