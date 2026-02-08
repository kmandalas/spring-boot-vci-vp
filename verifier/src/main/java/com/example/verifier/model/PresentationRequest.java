package com.example.verifier.model;

import com.nimbusds.jose.jwk.ECKey;

/**
 * Holds the authorization request data and the ephemeral encryption key pair.
 * The private key is used to decrypt the wallet's JWE response.
 * The context parameters (clientId, responseUri, nonce, ephemeralKeyThumbprint) are used for mDoc DeviceAuth verification.
 *
 * @param authorizationRequest   The signed JAR (JWT Authorization Request)
 * @param encryptionKey          Ephemeral EC key pair for JWE decryption
 * @param clientId               The verifier's client_id (x509_hash format)
 * @param responseUri            The endpoint where wallet posts the VP response
 * @param nonce                  Random nonce for replay protection
 * @param ephemeralKeyThumbprint JWK thumbprint of ephemeral key (for mDoc SessionTranscript)
 * @param expectedFormat         Expected credential format from DCQL query
 */
public record PresentationRequest(
        String authorizationRequest,
        ECKey encryptionKey,
        String clientId,
        String responseUri,
        String nonce,
        String ephemeralKeyThumbprint,
        CredentialFormat expectedFormat
) {
}
