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
        Instant expiresAt,
        String statusListId,
        Integer statusListIdx
) {
    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_REVOKED = "REVOKED";

    /**
     * Constructor without status list fields (for backward compatibility).
     */
    public WalletUnitAttestation(UUID wuaId, String walletPublicKeyThumbprint, String wscdType,
                                  String wscdSecurityLevel, Instant issuedAt, Instant expiresAt) {
        this(wuaId, walletPublicKeyThumbprint, STATUS_ACTIVE, wscdType, wscdSecurityLevel,
             issuedAt, expiresAt, null, null);
    }

    /**
     * Constructor with status list fields.
     */
    public WalletUnitAttestation(UUID wuaId, String walletPublicKeyThumbprint, String wscdType,
                                  String wscdSecurityLevel, Instant issuedAt, Instant expiresAt,
                                  String statusListId, int statusListIdx) {
        this(wuaId, walletPublicKeyThumbprint, STATUS_ACTIVE, wscdType, wscdSecurityLevel,
             issuedAt, expiresAt, statusListId, statusListIdx);
    }

}
