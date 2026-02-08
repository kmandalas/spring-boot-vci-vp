package com.example.verifier.service.credential;

/**
 * Context for mDoc DeviceAuth verification.
 * Contains the SessionTranscript parameters that must match what the wallet used when signing.
 *
 * <h2>OID4VP SessionTranscript Structure (ISO 18013-7 Annex B / EUDI Reference)</h2>
 * <pre>
 * SessionTranscript = [
 *   null,                        // DeviceEngagement (null for online OID4VP)
 *   null,                        // EReaderKey (null for online OID4VP)
 *   Handover                     // Handover structure for OID4VP
 * ]
 *
 * Handover = [
 *   "OpenID4VPHandover",                           // identifier string
 *   SHA-256(CBOR.encode(OID4VPHandoverInfo))       // hash of CBOR-encoded handover info
 * ]
 *
 * OID4VPHandoverInfo = [
 *   clientId,                    // tstr: client_id (plain, NOT hashed)
 *   nonce,                       // tstr: nonce from authorization request
 *   ephemeralKeyThumbprint,      // bstr or null: JWK thumbprint of ephemeral key
 *   responseUri                  // tstr: response_uri (plain, NOT hashed)
 * ]
 * </pre>
 *
 * <h2>Android App Implementation Note</h2>
 * When implementing DeviceAuth on the Android wallet side:
 * <ol>
 *   <li>Extract client_id, response_uri, nonce, ephemeral key from the authorization request (JAR)</li>
 *   <li>Build OID4VPHandoverInfo: [clientId, nonce, ephemeralKeyThumbprint, responseUri]</li>
 *   <li>CBOR-encode OID4VPHandoverInfo, then SHA-256 hash it</li>
 *   <li>Build Handover: ["OpenID4VPHandover", handoverInfoHash]</li>
 *   <li>Build SessionTranscript: [null, null, Handover]</li>
 *   <li>Build DeviceAuthentication: ["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]</li>
 *   <li>Sign CBOR-encoded DeviceAuthentication with device private key (the key bound in MSO.deviceKeyInfo)</li>
 *   <li>Create COSE_Sign1 with detached payload (payload = null in structure)</li>
 *   <li>Include the COSE_Sign1 as deviceSignature in DeviceSigned.deviceAuth</li>
 * </ol>
 *
 * <h2>DeviceResponse Structure</h2>
 * <pre>
 * DeviceResponse = {
 *   "version": "1.0",
 *   "documents": [
 *     {
 *       "docType": "eu.europa.ec.eudi.pda1.1",
 *       "issuerSigned": { ... },
 *       "deviceSigned": {
 *         "nameSpaces": {},          // Empty for now (no device-signed claims)
 *         "deviceAuth": {
 *           "deviceSignature": COSE_Sign1   // Signature over DeviceAuthentication
 *         }
 *       }
 *     }
 *   ]
 * }
 * </pre>
 *
 * @param clientId               The client_id from the authorization request (e.g., "x509_hash:SHA256:...")
 * @param responseUri            The response_uri where the VP will be posted
 * @param nonce                  The nonce from the authorization request
 * @param ephemeralKeyThumbprint The JWK thumbprint of the ephemeral encryption key (may be null)
 */
public record MDocVerificationContext(
        String clientId,
        String responseUri,
        String nonce,
        String ephemeralKeyThumbprint
) {
    /**
     * Creates a context indicating DeviceAuth verification should be skipped.
     * Use this when the presentation request context is not available.
     */
    public static MDocVerificationContext skipDeviceAuth() {
        return null;
    }
}
