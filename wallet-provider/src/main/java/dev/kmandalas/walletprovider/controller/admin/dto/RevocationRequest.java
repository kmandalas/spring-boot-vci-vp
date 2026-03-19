package dev.kmandalas.walletprovider.controller.admin.dto;

public record RevocationRequest(
        String reason,
        String adminUser
) {}
