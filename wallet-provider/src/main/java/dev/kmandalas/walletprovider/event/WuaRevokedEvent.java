package dev.kmandalas.walletprovider.event;

import java.time.Instant;
import java.util.UUID;

public record WuaRevokedEvent(
        UUID wuaId,
        String reason,
        String adminUser,
        Instant revokedAt
) {}
