package com.example.issuer.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "app.metadata")
public class AppMetadataConfig {

    private Endpoints endpoints;
    private Claims claims;

    // Getters and setters

    public static class Endpoints {
        private String issuer;
        private String authorization;
        private String credential;
        private String statusList;

        // Getters and setters
        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getAuthorization() {
            return authorization;
        }

        public void setAuthorization(String authorization) {
            this.authorization = authorization;
        }

        public String getCredential() {
            return credential;
        }

        public void setCredential(String credential) {
            this.credential = credential;
        }

        public String getStatusList() {
            return statusList;
        }

        public void setStatusList(String statusList) {
            this.statusList = statusList;
        }
    }

    public static class Claims {
        private String audience;
        private String vct;
        private String iss;

        // Getters and setters
        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public String getVct() {
            return vct;
        }

        public void setVct(String vct) {
            this.vct = vct;
        }

        public String getIss() {
            return iss;
        }

        public void setIss(String iss) {
            this.iss = iss;
        }
    }

    // Getters and setters for AppMetadataConfig
    public Endpoints getEndpoints() {
        return endpoints;
    }

    public void setEndpoints(Endpoints endpoints) {
        this.endpoints = endpoints;
    }

    public Claims getClaims() {
        return claims;
    }

    public void setClaims(Claims claims) {
        this.claims = claims;
    }

}

