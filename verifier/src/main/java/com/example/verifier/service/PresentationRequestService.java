package com.example.verifier.service;

import com.example.verifier.model.PresentationRequest;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for managing presentation requests and VP response encryption.
 * Handles ephemeral key generation, JAR signing, and JWE decryption for direct_post.jwt response mode.
 */
@Service
public class PresentationRequestService {

    private final Map<String, PresentationRequest> requestStore = new ConcurrentHashMap<>();
    private final JarSigningService jarSigningService;

    public PresentationRequestService(JarSigningService jarSigningService) {
        this.jarSigningService = jarSigningService;
    }

    /**
     * Returns the x509_hash client_id from the signing service.
     */
    public String getClientId() {
        return jarSigningService.getClientId();
    }

    /**
     * Creates and stores a new presentation request with ephemeral encryption key.
     * The request is signed as a JWT (JAR) with x5c header containing the verifier's certificate.
     *
     * @param requestId         Pre-generated request ID
     * @param responseUri       The endpoint where wallet will POST the response
     * @param dcqlQuery          The DCQL query for credential request
     * @param baseClientMetadata Base client metadata (name, logo, purpose)
     */
    public void createPresentationRequest(
            String requestId,
            String responseUri,
            Map<String, Object> dcqlQuery,
            Map<String, Object> baseClientMetadata
    ) throws Exception {
        String nonce = UUID.randomUUID().toString();

        // Generate ephemeral EC key pair for response encryption (P-256 / ECDH-ES)
        ECKey encryptionKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.ENCRYPTION)
                .keyID(UUID.randomUUID().toString())
                .algorithm(JWEAlgorithm.ECDH_ES)
                .generate();

        // Build client_metadata with encryption parameters
        Map<String, Object> clientMetadata = new LinkedHashMap<>(baseClientMetadata);
        clientMetadata.put("jwks", Map.of(
                "keys", List.of(encryptionKey.toPublicJWK().toJSONObject())
        ));
        clientMetadata.put("authorization_encrypted_response_alg", "ECDH-ES");
        clientMetadata.put("authorization_encrypted_response_enc", "A256GCM");

        // Build the authorization request claims
        Map<String, Object> authorizationRequest = new LinkedHashMap<>();
        authorizationRequest.put("client_id", getClientId()); // x509_hash:<hash>
        authorizationRequest.put("response_type", "vp_token");
        authorizationRequest.put("response_mode", "direct_post.jwt");
        authorizationRequest.put("response_uri", responseUri);
        authorizationRequest.put("nonce", nonce);
        authorizationRequest.put("dcql_query", dcqlQuery);
        authorizationRequest.put("client_metadata", clientMetadata);

        // Sign the authorization request as JWT (JAR with x5c header)
        String signedJwt = jarSigningService.signAuthorizationRequest(authorizationRequest);

        // Store signed JWT with encryption key
        requestStore.put(requestId, new PresentationRequest(signedJwt, encryptionKey));
    }

    /**
     * Retrieves the authorization request JSON for the given request ID.
     */
    public String getAuthorizationRequest(String requestId) {
        PresentationRequest request = requestStore.get(requestId);
        return request != null ? request.authorizationRequest() : null;
    }

    /**
     * Decrypts a JWE-encrypted VP response using the stored ephemeral private key.
     *
     * @param requestId The request ID to look up the decryption key
     * @param jweString The encrypted JWE string from the wallet
     * @return The decrypted VP token payload
     */
    public String decryptVpResponse(String requestId, String jweString) throws Exception {
        PresentationRequest request = requestStore.get(requestId);
        if (request == null) {
            throw new IllegalArgumentException("Request not found: " + requestId);
        }

        ECKey privateKey = request.encryptionKey();

        // Parse and decrypt the JWE
        JWEObject jweObject = JWEObject.parse(jweString);

        // Verify the algorithm matches what we expect
        if (!JWEAlgorithm.ECDH_ES.equals(jweObject.getHeader().getAlgorithm())) {
            throw new IllegalArgumentException("Unexpected JWE algorithm: " + jweObject.getHeader().getAlgorithm());
        }

        EncryptionMethod enc = jweObject.getHeader().getEncryptionMethod();
        if (!EncryptionMethod.A256GCM.equals(enc) && !EncryptionMethod.A128GCM.equals(enc)) {
            throw new IllegalArgumentException("Unexpected encryption method: " + enc);
        }

        // Decrypt using the ephemeral private key
        ECDHDecrypter decrypter = new ECDHDecrypter(privateKey);
        jweObject.decrypt(decrypter);

        return jweObject.getPayload().toString();
    }

    /**
     * Removes a request from the store (cleanup after processing).
     */
    public void removeRequest(String requestId) {
        requestStore.remove(requestId);
    }

    /**
     * Checks if a request exists in the store.
     */
    public boolean hasRequest(String requestId) {
        return requestStore.containsKey(requestId);
    }

}
