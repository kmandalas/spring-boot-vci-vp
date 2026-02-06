package com.example.wpadm.model;

import java.time.Instant;
import java.util.UUID;

public record AdminUser(
    UUID id,
    String username,
    String passwordHash,
    String totpSecret,
    boolean totpEnabled,
    Instant createdAt
) {}
