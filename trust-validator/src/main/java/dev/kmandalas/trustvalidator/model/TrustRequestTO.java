package dev.kmandalas.trustvalidator.model;

import java.util.List;

/**
 * Request body for the /trust endpoint.
 * {@code chain} is a list of Base64-encoded DER certificates (leaf first, root last).
 */
public record TrustRequestTO(
        List<String> chain,
        VerificationContextTO verificationContext,
        String useCase
) {}
