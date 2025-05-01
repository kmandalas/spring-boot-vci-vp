package com.example.verifier.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "app")
public class AppConfig {

    private String requestUriStore;
    private String deepLinkPrefix;
    private String issuerJwksUrl;
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

    public String getIssuerJwksUrl() {
        return issuerJwksUrl;
    }

    public void setIssuerJwksUrl(String issuerJwksUrl) {
        this.issuerJwksUrl = issuerJwksUrl;
    }

    public String getResponseUri() {
        return responseUri;
    }

    public void setResponseUri(String responseUri) {
        this.responseUri = responseUri;
    }

}
