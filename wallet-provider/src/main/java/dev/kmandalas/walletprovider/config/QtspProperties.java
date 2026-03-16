package dev.kmandalas.walletprovider.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "wp.qtsp")
public class QtspProperties {

    private boolean enabled = false;
    private List<String> trustedIssuers = List.of();
    private boolean trustValidatorEnabled = false;
    private String trustValidatorUrl = "http://localhost:8090";

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public List<String> getTrustedIssuers() {
        return trustedIssuers;
    }

    public void setTrustedIssuers(List<String> trustedIssuers) {
        this.trustedIssuers = trustedIssuers;
    }

    public boolean isTrustValidatorEnabled() {
        return trustValidatorEnabled;
    }

    public void setTrustValidatorEnabled(boolean trustValidatorEnabled) {
        this.trustValidatorEnabled = trustValidatorEnabled;
    }

    public String getTrustValidatorUrl() {
        return trustValidatorUrl;
    }

    public void setTrustValidatorUrl(String trustValidatorUrl) {
        this.trustValidatorUrl = trustValidatorUrl;
    }
}
