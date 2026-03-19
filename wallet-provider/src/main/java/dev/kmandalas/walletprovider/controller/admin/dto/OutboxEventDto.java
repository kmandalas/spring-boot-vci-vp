package dev.kmandalas.walletprovider.controller.admin.dto;

import java.time.Instant;

public record OutboxEventDto(
        long id,
        String type,
        String key,
        Object payload,
        Instant createdAt
) {}
