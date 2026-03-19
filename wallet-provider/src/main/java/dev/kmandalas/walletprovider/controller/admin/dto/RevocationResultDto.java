package dev.kmandalas.walletprovider.controller.admin.dto;

import java.util.UUID;

public record RevocationResultDto(
        UUID wuaId,
        String status,
        String message
) {}
