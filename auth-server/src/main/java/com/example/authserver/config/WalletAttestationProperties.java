package com.example.authserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for Wallet Instance Attestation (WIA) authentication.
 * Configures trusted Wallet Providers and validation parameters.
 */
@Component
@ConfigurationProperties(prefix = "app.wallet-attestation")
public class WalletAttestationProperties {

    /**
     * List of trusted Wallet Provider issuer URLs.
     * WIA JWTs must be signed by one of these issuers.
     */
    private List<String> trustedIssuers = new ArrayList<>();

    /**
     * Maximum age of PoP JWT in seconds (default: 5 minutes).
     */
    private long maxPopAgeSeconds = 300;

    /**
     * Maximum age of WIA JWT in seconds (default: 24 hours).
     */
    private long maxWiaAgeSeconds = 86400;

    public List<String> getTrustedIssuers() {
        return trustedIssuers;
    }

    public void setTrustedIssuers(List<String> trustedIssuers) {
        this.trustedIssuers = trustedIssuers;
    }

    public long getMaxPopAgeSeconds() {
        return maxPopAgeSeconds;
    }

    public void setMaxPopAgeSeconds(long maxPopAgeSeconds) {
        this.maxPopAgeSeconds = maxPopAgeSeconds;
    }

    public long getMaxWiaAgeSeconds() {
        return maxWiaAgeSeconds;
    }

    public void setMaxWiaAgeSeconds(long maxWiaAgeSeconds) {
        this.maxWiaAgeSeconds = maxWiaAgeSeconds;
    }

    /**
     * Check if the given issuer is in the list of trusted issuers.
     *
     * @param issuer the issuer URL to check
     * @return true if the issuer is trusted, false otherwise
     */
    public boolean isTrustedIssuer(String issuer) {
        return trustedIssuers.contains(issuer);
    }

}
