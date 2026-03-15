package dev.kmandalas.qtspmock.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CredentialAuthorizeResponse(
        @JsonProperty("SAD") String sad,
        @JsonProperty("expiresIn") long expiresIn
) {}
