package com.example.wpadm.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "wallet-provider")
public record WalletProviderClientProperties(
        String baseUrl,
        String apiKey,
        int pollIntervalSeconds
) {}
