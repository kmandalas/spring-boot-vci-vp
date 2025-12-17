package com.example.walletprovider.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class WuaCredentialRequest {

    private Proof proof;

    @JsonProperty("key_attestation")
    private KeyAttestation keyAttestation;

    public static class Proof {
        @JsonProperty("proof_type")
        private String proofType;

        private String jwt;

        public String getProofType() {
            return proofType;
        }

        public void setProofType(String proofType) {
            this.proofType = proofType;
        }

        public String getJwt() {
            return jwt;
        }

        public void setJwt(String jwt) {
            this.jwt = jwt;
        }
    }

    public static class KeyAttestation {
        @JsonProperty("attestation_type")
        private String attestationType;

        @JsonProperty("certificate_chain")
        private List<String> certificateChain;

        public String getAttestationType() {
            return attestationType;
        }

        public void setAttestationType(String attestationType) {
            this.attestationType = attestationType;
        }

        public List<String> getCertificateChain() {
            return certificateChain;
        }

        public void setCertificateChain(List<String> certificateChain) {
            this.certificateChain = certificateChain;
        }
    }

    public Proof getProof() {
        return proof;
    }

    public void setProof(Proof proof) {
        this.proof = proof;
    }

    public KeyAttestation getKeyAttestation() {
        return keyAttestation;
    }

    public void setKeyAttestation(KeyAttestation keyAttestation) {
        this.keyAttestation = keyAttestation;
    }
}
