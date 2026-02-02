package com.example.verifier.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "app")
public class AppConfig {

    private String requestUriStore;
    private String deepLinkPrefix;
    private List<String> trustedIssuers = new ArrayList<>();
    private String responseUri;

    // Getters and setters

    public String getRequestUriStore() {
        return requestUriStore;
    }

    public void setRequestUriStore(String requestUriStore) {
        this.requestUriStore = requestUriStore;
    }

    public String getDeepLinkPrefix() {
        return deepLinkPrefix;
    }

    public void setDeepLinkPrefix(String deepLinkPrefix) {
        this.deepLinkPrefix = deepLinkPrefix;
    }

    public List<String> getTrustedIssuers() {
        return trustedIssuers;
    }

    public void setTrustedIssuers(List<String> trustedIssuers) {
        this.trustedIssuers = trustedIssuers;
    }

    /**
     * Check if a credential issuer is in the trusted issuers list.
     * @param issuer the iss claim from the credential JWT
     * @return true if trusted, false otherwise
     */
    public boolean isTrustedIssuer(String issuer) {
        if (issuer == null || trustedIssuers.isEmpty()) {
            return false;
        }
        return trustedIssuers.stream()
                .anyMatch(trusted -> issuer.equals(trusted) || issuer.startsWith(trusted));
    }

    public String getResponseUri() {
        return responseUri;
    }

    public void setResponseUri(String responseUri) {
        this.responseUri = responseUri;
    }

}
