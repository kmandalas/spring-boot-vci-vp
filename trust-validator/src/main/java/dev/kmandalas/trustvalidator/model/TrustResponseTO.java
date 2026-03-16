package dev.kmandalas.trustvalidator.model;

/**
 * Response body for the /trust endpoint.
 */
public record TrustResponseTO(boolean trusted, String trustAnchor) {

    public static TrustResponseTO trusted(String trustAnchorBase64) {
        return new TrustResponseTO(true, trustAnchorBase64);
    }

    public static TrustResponseTO notTrusted() {
        return new TrustResponseTO(false, null);
    }
}
