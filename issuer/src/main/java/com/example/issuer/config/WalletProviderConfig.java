package com.example.issuer.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "app.wallet-provider")
public class WalletProviderConfig {

    private List<String> trustedIssuers = new ArrayList<>();
    private String allowedWscdTypes;

    public List<String> getTrustedIssuers() {
        return trustedIssuers;
    }

    public void setTrustedIssuers(List<String> trustedIssuers) {
        this.trustedIssuers = trustedIssuers;
    }

    public String getAllowedWscdTypes() {
        return allowedWscdTypes;
    }

    public void setAllowedWscdTypes(String allowedWscdTypes) {
        this.allowedWscdTypes = allowedWscdTypes;
    }

    /**
     * Check if a WUA issuer is in the trusted issuers list.
     * @param issuer the iss claim from the WUA
     * @return true if trusted, false otherwise
     */
    public boolean isTrustedIssuer(String issuer) {
        if (issuer == null || trustedIssuers.isEmpty()) {
            return false;
        }
        return trustedIssuers.stream()
                .anyMatch(trusted -> issuer.equals(trusted) || issuer.startsWith(trusted));
    }

    /**
     * Check if a WSCD type is allowed based on configuration.
     * @param wscdType the storage type from WUA (e.g., "software", "tee", "strongbox")
     * @return true if allowed, false otherwise
     */
    public boolean isWscdTypeAllowed(String wscdType) {
        if ("all".equalsIgnoreCase(allowedWscdTypes)) {
            return true;
        }
        if (allowedWscdTypes == null || wscdType == null) {
            return false;
        }
        List<String> allowed = List.of(allowedWscdTypes.toLowerCase().split(","));
        return allowed.stream()
                .map(String::trim)
                .anyMatch(t -> t.equalsIgnoreCase(wscdType));
    }
}
