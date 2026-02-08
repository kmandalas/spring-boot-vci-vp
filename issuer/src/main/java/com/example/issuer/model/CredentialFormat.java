package com.example.issuer.model;

public enum CredentialFormat {

    DC_SD_JWT("dc+sd-jwt"),
    MSO_MDOC("mso_mdoc");

    private final String value;

    CredentialFormat(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    /**
     * Resolves a format string to a CredentialFormat enum constant.
     *
     * @param format the format string from the credential request
     * @return the matching CredentialFormat
     * @throws IllegalArgumentException if the format is not supported
     */
    public static CredentialFormat fromValue(String format) {
        if (format == null || format.isEmpty()) {
            return DC_SD_JWT;
        }
        for (CredentialFormat cf : values()) {
            if (cf.value.equals(format)) {
                return cf;
            }
        }
        throw new IllegalArgumentException("Unsupported credential format: " + format);
    }

}
