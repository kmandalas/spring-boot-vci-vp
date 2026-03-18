package com.example.wpadm.client.dto;

import java.util.UUID;

public record RevocationResultDto(
        UUID wuaId,
        String status,
        String message
) {}
