package dev.kmandalas.qtspmock.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record CredentialAuthorizeRequest(
        @JsonProperty("credentialID") String credentialId,
        @JsonProperty("numSignatures") Integer numSignatures,
        @JsonProperty("hash") List<String> hash,
        @JsonProperty("PIN") String pin
) {}
