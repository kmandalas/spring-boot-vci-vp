package com.example.wpadm.model;

public record DashboardStats(
    long totalWuas,
    long activeWuas,
    long revokedWuas,
    long expiringWuas
) {}
