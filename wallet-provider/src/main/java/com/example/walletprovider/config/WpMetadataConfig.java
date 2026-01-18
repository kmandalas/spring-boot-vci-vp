package com.example.walletprovider.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "wp.metadata")
public class WpMetadataConfig {

    private Endpoints endpoints = new Endpoints();
    private Claims claims = new Claims();
    private Provider provider = new Provider();
    private Time time = new Time();

    public static class Endpoints {
        private String issuer;
        private String credential;
        private String jwks;
        private String statusList;

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getCredential() {
            return credential;
        }

        public void setCredential(String credential) {
            this.credential = credential;
        }

        public String getJwks() {
            return jwks;
        }

        public void setJwks(String jwks) {
            this.jwks = jwks;
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
        private String iss;

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public String getIss() {
            return iss;
        }

        public void setIss(String iss) {
            this.iss = iss;
        }
    }

    public static class Provider {
        private String id;
        private String name;
        private String solutionVersion;
        private String certificationInformation = "N/A";  // TS3: wallet_solution_certification_information
        private String clientId = "wallet-dev";           // TS3: sub claim (OAuth client ID)
        private String wscdCertificationInformation = "N/A";  // TS3: wscd_certification_information

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getSolutionVersion() {
            return solutionVersion;
        }

        public void setSolutionVersion(String solutionVersion) {
            this.solutionVersion = solutionVersion;
        }

        public String getCertificationInformation() {
            return certificationInformation;
        }

        public void setCertificationInformation(String certificationInformation) {
            this.certificationInformation = certificationInformation;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getWscdCertificationInformation() {
            return wscdCertificationInformation;
        }

        public void setWscdCertificationInformation(String wscdCertificationInformation) {
            this.wscdCertificationInformation = wscdCertificationInformation;
        }
    }

    public static class Time {
        private long nonceTtlSeconds = 300;
        private long maxProofAgeSeconds = 300;
        private long wuaTtlSeconds = 86400;

        public long getNonceTtlSeconds() {
            return nonceTtlSeconds;
        }

        public void setNonceTtlSeconds(long nonceTtlSeconds) {
            this.nonceTtlSeconds = nonceTtlSeconds;
        }

        public long getMaxProofAgeSeconds() {
            return maxProofAgeSeconds;
        }

        public void setMaxProofAgeSeconds(long maxProofAgeSeconds) {
            this.maxProofAgeSeconds = maxProofAgeSeconds;
        }

        public long getWuaTtlSeconds() {
            return wuaTtlSeconds;
        }

        public void setWuaTtlSeconds(long wuaTtlSeconds) {
            this.wuaTtlSeconds = wuaTtlSeconds;
        }
    }

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

    public Provider getProvider() {
        return provider;
    }

    public void setProvider(Provider provider) {
        this.provider = provider;
    }

    public Time getTime() {
        return time;
    }

    public void setTime(Time time) {
        this.time = time;
    }
}
