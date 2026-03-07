package dev.kmandalas.walletprovider.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "firebase.app-check")
public record AppCheckProperties(boolean enabled, String projectNumber, String appId) {
}
