package dev.kmandalas.qtspmock.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record CredentialsListResponse(
        @JsonProperty("credentialIDs") List<String> credentialIds
) {}
