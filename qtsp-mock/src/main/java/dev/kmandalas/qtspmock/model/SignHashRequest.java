package dev.kmandalas.qtspmock.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record SignHashRequest(
        @JsonProperty("credentialID") String credentialId,
        @JsonProperty("SAD") String sad,
        @JsonProperty("hash") List<String> hash,
        @JsonProperty("hashAlgo") String hashAlgo,
        @JsonProperty("signAlgo") String signAlgo
) {}
