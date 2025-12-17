package com.example.walletprovider.model;

import java.security.PublicKey;

public record KeyAttestationData(
        PublicKey walletPublicKey,
        String wscdType,
        String wscdSecurityLevel,
        int attestationVersion,
        byte[] attestationChallenge
) {
    public static final String WSCD_TYPE_STRONGBOX = "strongbox";
    public static final String WSCD_TYPE_TEE = "tee";
    public static final String WSCD_TYPE_SOFTWARE = "software";

    public static final String SECURITY_LEVEL_HARDWARE = "hardware";
    public static final String SECURITY_LEVEL_SOFTWARE = "software";
}
