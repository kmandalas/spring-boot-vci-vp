package dev.kmandalas.qtspmock.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CredentialsListRequest(
        @JsonProperty("userID") String userId,
        @JsonProperty("maxResults") Integer maxResults
) {}
