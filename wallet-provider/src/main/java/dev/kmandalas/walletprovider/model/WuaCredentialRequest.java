package dev.kmandalas.walletprovider.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

public record WuaCredentialRequest(
        Proof proof,
        @JsonProperty("key_attestation") KeyAttestation keyAttestation
) {
    public record Proof(
            @JsonProperty("proof_type") String proofType,
            String jwt
    ) {}

    public record KeyAttestation(
            @JsonProperty("attestation_type") String attestationType,
            @JsonProperty("certificate_chain") List<String> certificateChain,
            @JsonProperty("qtsp_credential_info") QtspCredentialInfo qtspCredentialInfo
    ) {}

    /**
     * Mirrors the CSC API v2 credentials/info response shape.
     * Sent by the wallet when attestation_type is "qtsp_attestation".
     */
    public record QtspCredentialInfo(
            @JsonProperty("key") KeyInfo key,
            @JsonProperty("cert") CertInfo cert,
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
    }
}
