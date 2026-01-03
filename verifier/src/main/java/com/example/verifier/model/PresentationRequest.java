package com.example.verifier.model;

import com.nimbusds.jose.jwk.ECKey;

/**
 * Holds the authorization request JSON and the ephemeral encryption key pair.
 * The private key is used to decrypt the wallet's JWE response.
 */
public record PresentationRequest(
        String authorizationRequest,
        ECKey encryptionKey
) {}
