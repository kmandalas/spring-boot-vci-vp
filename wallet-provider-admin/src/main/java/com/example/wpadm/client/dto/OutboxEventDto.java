package com.example.wpadm.client.dto;

import java.time.Instant;

public record OutboxEventDto(
        long id,
        String type,
        String key,
        String payload,
        Instant createdAt
) {}
