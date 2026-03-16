package dev.kmandalas.qtspmock.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record SignHashResponse(
        @JsonProperty("signatures") List<String> signatures
) {}
