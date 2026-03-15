package dev.kmandalas.qtspmock.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

public record CredentialInfoResponse(
        @JsonProperty("description") String description,
        @JsonProperty("key") KeyInfo key,
        @JsonProperty("cert") CertInfo cert,
        @JsonProperty("auth") AuthInfo auth,
        @JsonProperty("SCAL") String scal
) {
    public record KeyInfo(
            @JsonProperty("status") String status,
            @JsonProperty("algo") List<String> algo,
            @JsonProperty("len") int len,
            @JsonProperty("curve") String curve
    ) {}

    public record CertInfo(
            @JsonProperty("status") String status,
            @JsonProperty("certificates") List<String> certificates,
            @JsonProperty("issuerDN") String issuerDN,
            @JsonProperty("subjectDN") String subjectDN
    ) {}

    public record AuthInfo(
            @JsonProperty("mode") String mode,
            @JsonProperty("expression") List<String> expression
    ) {}
}
