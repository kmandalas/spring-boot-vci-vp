package dev.kmandalas.verifier.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "app")
public class AppConfig {

    private String requestUriStore;
    private String deepLinkPrefix;
    private List<String> trustedIssuers = new ArrayList<>();
    private String responseUri;
    private boolean statusCheckEnabled = true;

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

    public boolean isStatusCheckEnabled() {
        return statusCheckEnabled;
    }

    public void setStatusCheckEnabled(boolean statusCheckEnabled) {
        this.statusCheckEnabled = statusCheckEnabled;
    }

    private ClientMetadata clientMetadata = new ClientMetadata();

    public ClientMetadata getClientMetadata() {
        return clientMetadata;
    }

    public void setClientMetadata(ClientMetadata clientMetadata) {
        this.clientMetadata = clientMetadata;
    }

    private TrustValidatorConfig trustValidator = new TrustValidatorConfig();

    public TrustValidatorConfig getTrustValidator() {
        return trustValidator;
    }

    public void setTrustValidator(TrustValidatorConfig trustValidator) {
        this.trustValidator = trustValidator;
    }

    public static class ClientMetadata {
        private String clientName = "Demo Verifier Inc.";
        private String logoUri;
        private String purpose = "Verify your Portable Document A1 credentials";

        public String getClientName() { return clientName; }
        public void setClientName(String clientName) { this.clientName = clientName; }
        public String getLogoUri() { return logoUri; }
        public void setLogoUri(String logoUri) { this.logoUri = logoUri; }
        public String getPurpose() { return purpose; }
        public void setPurpose(String purpose) { this.purpose = purpose; }
    }

    public static class TrustValidatorConfig {
        private boolean enabled = false;
        private String url;
        private Map<String, String> vctToContext = new HashMap<>();
        private String defaultContext = "QEAA";

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public Map<String, String> getVctToContext() { return vctToContext; }
        public void setVctToContext(Map<String, String> vctToContext) { this.vctToContext = vctToContext; }
        public String getDefaultContext() { return defaultContext; }
        public void setDefaultContext(String defaultContext) { this.defaultContext = defaultContext; }
    }

}
