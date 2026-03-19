package dev.kmandalas.walletprovider.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "wp.admin-api")
public record AdminApiProperties(
        boolean enabled,
        String apiKey
) {}
