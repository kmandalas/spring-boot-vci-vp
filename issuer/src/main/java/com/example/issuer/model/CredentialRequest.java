package com.example.issuer.model;


public class CredentialRequest {

    private String format;
    private String credentialConfigurationId; // REQUIRED by spec
    private Proof proof;

    public String getFormat() {
        return format;
    }

    public String getCredentialConfigurationId() {
        return credentialConfigurationId;
    }

    public Proof getProof() {
        return proof;
    }

    public static class Proof {

        private String proofType; // Always "jwt" for now
        private String jwt;       // Wallet's proof of possession JWT

        public String getProofType() {
            return proofType;
        }

        public String getJwt() {
            return jwt;
        }
    }

}
