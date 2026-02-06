package com.example.wpadm.model;

import java.time.Instant;
import java.util.UUID;

public record WuaView(
    UUID wuaId,
    String walletPublicKeyThumbprint,
    String status,
    String wscdType,
    String wscdSecurityLevel,
    Instant issuedAt,
    Instant expiresAt,
    String statusListId,
    Integer statusListIdx
) {}
