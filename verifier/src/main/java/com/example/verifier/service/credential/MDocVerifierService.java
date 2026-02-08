package com.example.verifier.service.credential;

import com.authlete.cbor.*;
import com.authlete.cose.COSEEC2Key;
import com.authlete.cose.COSEKey;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSEVerifier;
import com.example.verifier.util.MDocCBORHelper;
import com.example.verifier.util.MDocDigestHelper;
import com.nimbusds.jose.jwk.JWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Service for verifying mDoc (ISO/IEC 18013-5:2021) presentations
 * using Authlete's CBOR library utilities.
 *
 * This implementation leverages Authlete's high-level API:
 * - COSESign1.build() for reconstructing COSE signatures
 * - CBORPairList.findByKey() for clean data extraction
 * - COSEVerifier for signature verification
 */
@Service
public class MDocVerifierService {

    private static final Logger logger = LoggerFactory.getLogger(MDocVerifierService.class);

    /**
     * Result of mDoc verification containing status and disclosed claims.
     */
    public record MDocValidationResult(boolean valid, Map<String, Object> disclosedClaims, String error) {
        public static MDocValidationResult success(Map<String, Object> claims) {
            return new MDocValidationResult(true, claims, null);
        }

        public static MDocValidationResult failure(String error) {
            return new MDocValidationResult(false, Map.of(), error);
        }
    }

    /**
     * Verify an mDoc DeviceResponse presentation (without DeviceAuth verification).
     * Use this overload when the presentation request context is not available.
     *
     * @param vpToken         Base64url-encoded CBOR DeviceResponse from wallet
     * @param issuerPublicKey Issuer's public key for IssuerAuth verification
     * @return MDocValidationResult with status and disclosed claims
     */
    public MDocValidationResult verifyMDocPresentation(String vpToken, JWK issuerPublicKey) {
        return verifyMDocPresentation(vpToken, issuerPublicKey, null);
    }

    /**
     * Verify an mDoc DeviceResponse presentation with full DeviceAuth verification.
     *
     * @param vpToken         Base64url-encoded CBOR DeviceResponse from wallet
     * @param issuerPublicKey Issuer's public key for IssuerAuth verification
     * @param context         SessionTranscript parameters for DeviceAuth verification (null to skip)
     * @return MDocValidationResult with status and disclosed claims
     */
    public MDocValidationResult verifyMDocPresentation(String vpToken, JWK issuerPublicKey,
                                                        MDocVerificationContext context) {
        try {
            // Step 1: Decode base64url-encoded CBOR
            byte[] deviceResponseBytes = Base64.getUrlDecoder().decode(vpToken);

            // Step 2: Parse DeviceResponse from CBOR (returns CBORPairList)
            CBORDecoder decoder = new CBORDecoder(deviceResponseBytes);
            Object deviceResponseObj = decoder.next();

            CBORPairList deviceResponseMap = (CBORPairList) deviceResponseObj;

            // Step 3: Get documents array
            CBORPair documentsPair = deviceResponseMap.findByKey("documents");
            Assert.notNull(documentsPair, "DeviceResponse must contain 'documents' field");

            CBORItemList documents = (CBORItemList) documentsPair.getValue();
            Assert.isTrue(!documents.getItems().isEmpty(), "DeviceResponse must contain at least one document");

            // Step 3.1: Parse first document (returns CBORPairList)
            CBORPairList documentMap = (CBORPairList) documents.getItems().getFirst();

            // Step 4: Parse common structures once (used by multiple verification methods)
            // Step 4.1: Extract IssuerSigned from document
            CBORPair issuerSignedPair = documentMap.findByKey("issuerSigned");
            Assert.notNull(issuerSignedPair, "issuerSigned must be present in document");
            CBORPairList issuerSignedMap = (CBORPairList) issuerSignedPair.getValue();

            // Step 4.2: Extract and build IssuerAuth COSESign1
            CBORPair issuerAuthPair = issuerSignedMap.findByKey("issuerAuth");
            Assert.notNull(issuerAuthPair, "issuerAuth must be present");
            CBORItemList issuerAuthList = (CBORItemList) issuerAuthPair.getValue();
            COSESign1 issuerAuth = COSESign1.build(issuerAuthList);

            // Step 4.3: Parse MSO (Mobile Security Object) from IssuerAuth payload
            CBORPairList msoMap = MDocCBORHelper.parseMSO(issuerAuth);

            // Step 5: Verify IssuerAuth (issuer's signature over MSO)
            verifyIssuerAuth(issuerAuth, issuerPublicKey);

            // Step 6: Verify ValidityInfo (credential expiration)
            verifyValidityInfo(msoMap);

            // Step 7: Verify Digests (disclosed items match MSO hashes)
            verifyDigests(msoMap, issuerSignedMap);

            // Step 8: Verify DeviceAuth (proof of possession) if context provided
            if (context != null) {
                verifyDeviceAuth(documentMap, msoMap, context);
            } else {
                logger.debug("Skipping DeviceAuth verification (no context provided)");
            }

            // Step 9: Extract disclosed claims
            Map<String, Object> disclosedClaims = extractDisclosedClaims(documentMap);

            logger.info("mDoc verification successful");
            return MDocValidationResult.success(disclosedClaims);

        } catch (Exception e) {
            logger.error("mDoc verification failed", e);
            return MDocValidationResult.failure(e.getMessage());
        }
    }

    /**
     * Verify the IssuerAuth (COSE_Sign1 signature over MSO).
     *
     * @param issuerAuth      Pre-built COSESign1 from IssuerAuth
     * @param issuerPublicKey Issuer's public key for signature verification
     */
    private void verifyIssuerAuth(COSESign1 issuerAuth, JWK issuerPublicKey) throws Exception {
        // Convert JWK to PublicKey for verification
        PublicKey publicKey = issuerPublicKey.toECKey().toPublicKey();

        // Create COSE verifier with issuer's public key
        COSEVerifier verifier = new COSEVerifier(publicKey);

        // Verify the IssuerAuth signature
        boolean verified = verifier.verify(issuerAuth);
        Assert.isTrue(verified, "IssuerAuth signature verification failed");

        logger.debug("IssuerAuth signature verified successfully");
    }

    /**
     * Verify the ValidityInfo (credential expiration) from MSO.
     *
     * Per ISO 18013-5, the MSO contains a validityInfo structure with:
     * - signed: Date/time when credential was issued
     * - validFrom: Date/time when credential becomes valid
     * - validUntil: Date/time when credential expires
     *
     * This method ensures the credential is currently within its validity period.
     *
     * @param msoMap Parsed MSO (Mobile Security Object) as CBORPairList
     */
    private void verifyValidityInfo(CBORPairList msoMap) {
        // Get validityInfo from MSO
        CBORPair validityInfoPair = msoMap.findByKey("validityInfo");
        Assert.notNull(validityInfoPair, "validityInfo must be present in MSO");

        CBORPairList validityInfoMap = (CBORPairList) validityInfoPair.getValue();

        // Extract validFrom and validUntil timestamps
        CBORPair validFromPair = validityInfoMap.findByKey("validFrom");
        CBORPair validUntilPair = validityInfoMap.findByKey("validUntil");

        Assert.notNull(validFromPair, "validFrom must be present in validityInfo");
        Assert.notNull(validUntilPair, "validUntil must be present in validityInfo");

        Object validFromObj = validFromPair.getValue();
        Object validUntilObj = validUntilPair.getValue();

        // Parse timestamps - CBOR dates are typically tagged items (tag 0) or tstrings (tag 1)
        Instant validFrom = MDocCBORHelper.parseInstantFromCBOR(validFromObj);
        Instant validUntil = MDocCBORHelper.parseInstantFromCBOR(validUntilObj);
        Instant now = Instant.now();

        // Validate temporal validity
        Assert.isTrue(!now.isBefore(validFrom),
                "Credential is not yet valid. validFrom: " + validFrom + ", current time: " + now);
        Assert.isTrue(!now.isAfter(validUntil),
                "Credential has expired. validUntil: " + validUntil + ", current time: " + now);

        logger.debug("ValidityInfo verified successfully (valid from {} until {})", validFrom, validUntil);
    }

    /**
     * Verify that disclosed IssuerSignedItems match their digests in the MSO.
     *
     * Per ISO 18013-5, the MSO contains valueDigests mapping namespace -> digestID -> hash.
     * This method verifies that each disclosed item's hash matches the corresponding digest
     * in the MSO, preventing tampering of disclosed values.
     *
     * @param msoMap          Parsed MSO (Mobile Security Object) containing valueDigests
     * @param issuerSignedMap IssuerSigned map containing disclosed nameSpaces
     * @throws Exception if digest verification fails
     */
    private void verifyDigests(CBORPairList msoMap, CBORPairList issuerSignedMap) throws Exception {
        // Step 1: Extract and validate digest algorithm
        CBORPair digestAlgorithmPair = msoMap.findByKey("digestAlgorithm");
        Assert.notNull(digestAlgorithmPair, "digestAlgorithm must be present in MSO");

        String digestAlgorithm = MDocDigestHelper.extractString(digestAlgorithmPair.getValue());
        Assert.isTrue("SHA-256".equals(digestAlgorithm),
                "Only SHA-256 digest algorithm is currently supported, but found: " + digestAlgorithm);

        // Step 2: Extract valueDigests from MSO
        CBORPair valueDigestsPair = msoMap.findByKey("valueDigests");
        Assert.notNull(valueDigestsPair, "valueDigests must be present in MSO");
        CBORPairList valueDigestsMap = (CBORPairList) valueDigestsPair.getValue();

        // Step 3: Extract disclosed nameSpaces from IssuerSigned
        CBORPair nameSpacesPair = issuerSignedMap.findByKey("nameSpaces");
        Assert.notNull(nameSpacesPair, "nameSpaces must be present in IssuerSigned");
        CBORPairList nameSpaces = (CBORPairList) nameSpacesPair.getValue();

        // Step 4: Verify digests for each namespace
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        int totalItemsVerified = 0;

        for (CBORPair nsEntry : nameSpaces.getPairs()) {
            String namespace = MDocDigestHelper.extractNamespace(nsEntry);

            // Get digest map for this namespace from MSO
            CBORPair nsDigestsPair = valueDigestsMap.findByKey(namespace);
            Assert.notNull(nsDigestsPair, "No digests found in MSO for namespace: " + namespace);
            CBORPairList nsDigestsMap = (CBORPairList) nsDigestsPair.getValue();

            // Verify each item in this namespace
            CBORItemList items = (CBORItemList) nsEntry.getValue();
            for (CBORItem itemObj : items.getItems()) {
                MDocDigestHelper.verifyItemDigest(itemObj, nsDigestsMap, sha256, namespace);
                totalItemsVerified++;
            }
        }

        logger.debug("Digest verification successful: {} items verified", totalItemsVerified);
    }

    /**
     * Verify DeviceAuth (proof of possession by the wallet).
     *
     * Per ISO 18013-5, DeviceAuth proves the wallet controls the private key
     * corresponding to the deviceKey in the MSO. For OID4VP online flow:
     *
     * 1. Extract deviceKey from MSO.deviceKeyInfo.deviceKey
     * 2. Build expected SessionTranscript from context (client_id, response_uri, nonce)
     * 3. Build DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]
     * 4. Verify deviceSignature over DeviceAuthentication using deviceKey
     *
     * @param documentMap The document containing DeviceSigned structure
     * @param msoMap      The MSO containing deviceKeyInfo
     * @param context     The verification context with SessionTranscript parameters
     * @throws Exception if DeviceAuth verification fails
     */
    private void verifyDeviceAuth(CBORPairList documentMap, CBORPairList msoMap,
                                   MDocVerificationContext context) throws Exception {
        // Step 1: Extract deviceKey from MSO
        COSEKey deviceKey = extractDeviceKey(msoMap);

        // Step 2: Extract docType from MSO
        CBORPair docTypePair = msoMap.findByKey("docType");
        Assert.notNull(docTypePair, "docType must be present in MSO");
        String docType = MDocDigestHelper.extractString(docTypePair.getValue());

        // Step 3: Extract DeviceSigned structure
        CBORPair deviceSignedPair = documentMap.findByKey("deviceSigned");
        Assert.notNull(deviceSignedPair, "deviceSigned must be present for DeviceAuth verification");
        CBORPairList deviceSignedMap = (CBORPairList) deviceSignedPair.getValue();

        // Step 4: Extract deviceAuth
        CBORPair deviceAuthPair = deviceSignedMap.findByKey("deviceAuth");
        Assert.notNull(deviceAuthPair, "deviceAuth must be present in deviceSigned");
        CBORPairList deviceAuthMap = (CBORPairList) deviceAuthPair.getValue();

        // Step 5: Extract deviceSignature (COSE_Sign1)
        CBORPair deviceSignaturePair = deviceAuthMap.findByKey("deviceSignature");
        Assert.notNull(deviceSignaturePair, "deviceSignature must be present in deviceAuth");
        CBORItemList deviceSignatureList = (CBORItemList) deviceSignaturePair.getValue();
        COSESign1 deviceSignature = COSESign1.build(deviceSignatureList);

        // Step 6: Extract DeviceNameSpacesBytes from deviceSigned
        CBORPair nameSpacesPair = deviceSignedMap.findByKey("nameSpaces");
        Assert.notNull(nameSpacesPair, "nameSpaces must be present in deviceSigned");
        CBORItem deviceNameSpacesItem = (CBORItem) nameSpacesPair.getValue();

        // Step 7: Build SessionTranscript for OID4VP
        byte[] sessionTranscriptBytes = buildSessionTranscript(context);

        // Step 8: Build DeviceAuthentication structure
        // DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]
        byte[] deviceAuthenticationBytes = buildDeviceAuthentication(
                sessionTranscriptBytes, docType, deviceNameSpacesItem);

        // Step 9: Verify the signature
        // The detached payload for COSE_Sign1 is the DeviceAuthentication CBOR
        verifyDeviceSignature(deviceSignature, deviceKey, deviceAuthenticationBytes);

        logger.debug("DeviceAuth verified successfully");
    }

    /**
     * Extract deviceKey (COSE_Key) from MSO.deviceKeyInfo.deviceKey
     */
    private COSEKey extractDeviceKey(CBORPairList msoMap) throws Exception {
        CBORPair deviceKeyInfoPair = msoMap.findByKey("deviceKeyInfo");
        Assert.notNull(deviceKeyInfoPair, "deviceKeyInfo must be present in MSO");
        CBORPairList deviceKeyInfoMap = (CBORPairList) deviceKeyInfoPair.getValue();

        CBORPair deviceKeyPair = deviceKeyInfoMap.findByKey("deviceKey");
        Assert.notNull(deviceKeyPair, "deviceKey must be present in deviceKeyInfo");

        // deviceKey is a COSE_Key (CBORPairList)
        CBORPairList deviceKeyCBOR = (CBORPairList) deviceKeyPair.getValue();

        // Build COSEKey from CBOR - for EC keys this will be COSEEC2Key
        return COSEKey.build(deviceKeyCBOR);
    }

    /**
     * Build SessionTranscript for OID4VP online flow (EUDI Reference Implementation).
     *
     * Per ISO 18013-7 Annex B and EUDI reference verifier, the SessionTranscript structure is:
     * <pre>
     * SessionTranscript = [
     *   null,                                        // DeviceEngagement (null for online)
     *   null,                                        // EReaderKey (null for online)
     *   Handover                                     // Handover structure
     * ]
     *
     * Handover = [
     *   "OpenID4VPHandover",                         // identifier string
     *   SHA-256(CBOR.encode(OID4VPHandoverInfo))     // hash of CBOR-encoded handover info
     * ]
     *
     * OID4VPHandoverInfo = [
     *   clientId,                                    // tstr: plain client_id (NOT hashed)
     *   nonce,                                       // tstr: plain nonce
     *   ephemeralKeyThumbprint,                      // bstr or null: JWK thumbprint bytes
     *   responseUri                                  // tstr: plain response_uri (NOT hashed)
     * ]
     * </pre>
     *
     * Key difference from our previous implementation:
     * - Individual fields are NOT hashed separately
     * - The entire OID4VPHandoverInfo array is CBOR-encoded, then SHA-256 hashed
     */
    private byte[] buildSessionTranscript(MDocVerificationContext context) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        // Build OID4VPHandoverInfo = [clientId, nonce, ephemeralKeyThumbprint, responseUri]
        // Note: ephemeralKeyThumbprint may be null
        CBORItem ephemeralKeyThumbprintItem;
        if (context.ephemeralKeyThumbprint() != null) {
            // JWK thumbprint is Base64url-encoded, decode to bytes
            byte[] thumbprintBytes = Base64.getUrlDecoder().decode(context.ephemeralKeyThumbprint());
            ephemeralKeyThumbprintItem = new CBORByteArray(thumbprintBytes);
        } else {
            ephemeralKeyThumbprintItem = CBORNull.INSTANCE;
        }

        CBORItemList oid4vpHandoverInfo = new CBORItemList(
                new CBORString(context.clientId()),
                new CBORString(context.nonce()),
                ephemeralKeyThumbprintItem,
                new CBORString(context.responseUri())
        );

        // CBOR-encode the handover info, then hash it
        byte[] handoverInfoBytes = oid4vpHandoverInfo.encode();
        byte[] handoverInfoHash = sha256.digest(handoverInfoBytes);

        // Build Handover = ["OpenID4VPHandover", handoverInfoHash]
        CBORItemList handover = new CBORItemList(
                new CBORString("OpenID4VPHandover"),
                new CBORByteArray(handoverInfoHash)
        );

        // Build SessionTranscript = [null, null, Handover]
        CBORItemList sessionTranscript = new CBORItemList(
                CBORNull.INSTANCE,
                CBORNull.INSTANCE,
                handover
        );

        return sessionTranscript.encode();
    }

    /**
     * Build DeviceAuthenticationBytes per ISO 18013-5.
     *
     * DeviceAuthentication = [
     *   "DeviceAuthentication",
     *   SessionTranscript,
     *   docType,
     *   DeviceNameSpacesBytes
     * ]
     * DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
     *
     * The COSE_Sign1 payload is DeviceAuthenticationBytes (tag-24 wrapped),
     * not the raw DeviceAuthentication array encoding.
     */
    private byte[] buildDeviceAuthentication(byte[] sessionTranscriptBytes, String docType,
                                              CBORItem deviceNameSpacesItem) throws Exception {
        // Parse SessionTranscript back to CBOR for inclusion
        CBORDecoder decoder = new CBORDecoder(sessionTranscriptBytes);
        CBORItem sessionTranscript = (CBORItem) decoder.next();

        CBORItemList deviceAuthentication = new CBORItemList(
                new CBORString("DeviceAuthentication"),
                sessionTranscript,
                new CBORString(docType),
                deviceNameSpacesItem
        );

        // Wrap as DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
        byte[] innerBytes = deviceAuthentication.encode();
        CBORTaggedItem tagged = new CBORTaggedItem(24, new CBORByteArray(innerBytes));
        return tagged.encode();
    }

    /**
     * Verify the device signature using the device's public key.
     *
     * @param deviceSignature The COSE_Sign1 signature from deviceAuth
     * @param deviceKey       The device's public key from MSO
     * @param payload         The DeviceAuthentication bytes (detached payload)
     */
    private void verifyDeviceSignature(COSESign1 deviceSignature, COSEKey deviceKey,
                                        byte[] payload) throws Exception {
        // For detached payload verification, we need to set the payload on the signature
        // Create a new COSESign1 with the payload attached
        CBORByteArray payloadItem = new CBORByteArray(payload);

        // Build a new COSESign1 with the payload for verification
        // The original deviceSignature has null payload (detached), we need to attach it
        // COSE_Sign1 = [protected, unprotected, payload, signature]
        CBORItem protectedHeader = deviceSignature.getProtectedHeader();
        CBORItem unprotectedHeader = deviceSignature.getUnprotectedHeader();
        CBORItem signature = deviceSignature.getSignature();

        // Handle null unprotected header (it may be null or empty map)
        if (unprotectedHeader == null) {
            unprotectedHeader = new CBORPairList();
        }

        CBORItemList signatureWithPayload = new CBORItemList(
                protectedHeader,
                unprotectedHeader,
                payloadItem,
                signature
        );

        COSESign1 signatureToVerify = COSESign1.build(signatureWithPayload);

        // Get the public key for verification
        PublicKey publicKey;
        if (deviceKey instanceof COSEEC2Key ec2Key) {
            publicKey = ec2Key.toECPublicKey();
        } else {
            throw new IllegalArgumentException("Unsupported device key type: " + deviceKey.getClass());
        }

        // Verify the signature
        COSEVerifier verifier = new COSEVerifier(publicKey);
        boolean verified = verifier.verify(signatureToVerify);
        Assert.isTrue(verified, "DeviceAuth signature verification failed");
    }

    /**
     * Extract and return disclosed claims from the mDoc presentation.
     */
    private Map<String, Object> extractDisclosedClaims(CBORPairList documentMap) {
        Map<String, Object> claims = new LinkedHashMap<>();

        try {
            // Navigate to nameSpaces
            CBORPairList issuerSignedMap = (CBORPairList) documentMap.findByKey("issuerSigned").getValue();
            CBORPairList nameSpaces = (CBORPairList) issuerSignedMap.findByKey("nameSpaces").getValue();

            // Extract all claims from all namespaces
            for (CBORPair nsEntry : nameSpaces.getPairs()) {
                String namespace = MDocDigestHelper.extractNamespace(nsEntry);
                Map<String, Object> namespaceClaims = new LinkedHashMap<>();

                CBORItemList items = (CBORItemList) nsEntry.getValue();
                for (CBORItem itemObj : items.getItems()) {
                    try {
                        // Decode IssuerSignedItem using helper
                        CBORPairList itemMap = MDocDigestHelper.decodeIssuerSignedItem(itemObj);

                        // Extract name and value
                        Object name = itemMap.findByKey("elementIdentifier").getValue();
                        Object value = itemMap.findByKey("elementValue").getValue();

                        String claimName = MDocDigestHelper.extractString(name);
                        Object claimValue = extractClaimValue(value);

                        namespaceClaims.put(claimName, claimValue);
                    } catch (Exception e) {
                        // Skip malformed items
                        logger.warn("Skipping malformed IssuerSignedItem: {}", e.getMessage());
                    }
                }

                claims.put(namespace, namespaceClaims);
            }
        } catch (Exception e) {
            logger.error("Error extracting disclosed claims", e);
        }

        return claims;
    }

    /**
     * Extract claim value from CBOR, handling maps and other types.
     */
    private Object extractClaimValue(Object value) {
        if (value instanceof CBORPairList pairList) {
            // Convert CBOR map to Java Map
            Map<String, Object> map = new LinkedHashMap<>();
            for (CBORPair pair : pairList.getPairs()) {
                String key = MDocDigestHelper.extractString(pair.getKey());
                Object val = extractClaimValue(pair.getValue());
                map.put(key, val);
            }
            return map;
        } else if (value instanceof CBORString) {
            return ((CBORString) value).getValue();
        } else if (value instanceof CBORInteger) {
            return ((CBORInteger) value).getValue();
        } else if (value instanceof CBORLong) {
            return ((CBORLong) value).getValue();
        } else if (value instanceof CBORDouble) {
            return ((CBORDouble) value).getValue();
        } else if (value instanceof CBORBoolean) {
            return ((CBORBoolean) value).getValue();
        } else if (value instanceof CBORByteArray) {
            return Base64.getEncoder().encodeToString(((CBORByteArray) value).getValue());
        } else {
            return value != null ? value.toString() : null;
        }
    }

}
