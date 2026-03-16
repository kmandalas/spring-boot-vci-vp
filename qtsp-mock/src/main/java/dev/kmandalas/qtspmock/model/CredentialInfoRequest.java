package dev.kmandalas.qtspmock.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CredentialInfoRequest(
        @JsonProperty("credentialID") String credentialId,
        @JsonProperty("certificates") String certificates,
        @JsonProperty("certInfo") Boolean certInfo,
        @JsonProperty("authInfo") Boolean authInfo
) {}
