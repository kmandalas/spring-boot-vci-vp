package com.example.verifier.model;

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
     * @param format the format string (e.g. from a DCQL query)
     * @return the matching CredentialFormat, or null if not recognized
     */
    public static CredentialFormat fromValue(String format) {
        if (format == null || format.isEmpty()) {
            return null;
        }
        for (CredentialFormat cf : values()) {
            if (cf.value.equals(format)) {
                return cf;
            }
        }
        return null;
    }

}
