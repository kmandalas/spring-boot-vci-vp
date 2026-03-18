package com.example.wpadm.client.dto;

public record RevocationRequest(
        String reason,
        String adminUser
) {}
