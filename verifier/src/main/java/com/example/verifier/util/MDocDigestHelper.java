package com.example.verifier.util;

import com.authlete.cbor.*;
import org.springframework.util.Assert;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

/**
 * Helper class for mDoc digest verification operations.
 * Handles CBOR unwrapping, type conversions, and digest extraction.
 */
public class MDocDigestHelper {

    /**
     * Decode an IssuerSignedItem from its CBOR-encoded form.
     * Handles tag 24 unwrapping and ByteArray decoding.
     *
     * @param itemObj The CBOR item (potentially wrapped with tag 24)
     * @return Decoded IssuerSignedItem as CBORPairList
     * @throws Exception if decoding fails
     */
    public static CBORPairList decodeIssuerSignedItem(CBORItem itemObj) throws Exception {
        // Unwrap tag 24 if present
        CBORItem unwrapped = (itemObj instanceof CBORTaggedItem)
            ? ((CBORTaggedItem) itemObj).getTagContent() : itemObj;

        // Extract bytes and decode
        byte[] bytes = ((CBORByteArray) unwrapped).getValue();
        return (CBORPairList) new CBORDecoder(bytes).next();
    }

    /**
     * Extract digestID from IssuerSignedItem, handling all CBOR numeric types.
     *
     * @param itemMap The decoded IssuerSignedItem map
     * @return The digestID as an integer
     */
    public static int extractDigestID(CBORPairList itemMap) {
        CBORPair digestIDPair = itemMap.findByKey("digestID");
        Assert.notNull(digestIDPair, "digestID must be present in IssuerSignedItem");

        Object value = digestIDPair.getValue();
        if (value instanceof CBORInteger) {
            return ((CBORInteger) value).getValue();
        } else if (value instanceof CBORLong) {
            return ((CBORLong) value).getValue().intValue();
        } else {
            return ((Number) value).intValue();
        }
    }

    /**
     * Extract namespace name from CBORPair, handling CBORString vs plain string.
     *
     * @param nsEntry The namespace entry from nameSpaces map
     * @return The namespace as a string
     */
    public static String extractNamespace(CBORPair nsEntry) {
        Object nsKeyObj = nsEntry.getKey();
        return extractString(nsKeyObj);
    }

    /**
     * Extract string value from CBOR object (handles CBORString).
     *
     * @param obj The CBOR object
     * @return The string value
     */
    public static String extractString(Object obj) {
        if (obj instanceof CBORString) {
            return ((CBORString) obj).getValue();
        }
        return obj.toString();
    }

    /**
     * Extract expected digest from MSO valueDigests for given namespace and digestID.
     *
     * @param nsDigestsMap The valueDigests map for a specific namespace
     * @param digestID The digestID to look up
     * @param namespace The namespace name (for error messages)
     * @return The expected digest bytes
     */
    public static byte[] getExpectedDigest(CBORPairList nsDigestsMap, int digestID, String namespace) {
        CBORPair expectedDigestPair = nsDigestsMap.findByKey(digestID);
        Assert.notNull(expectedDigestPair,
            String.format("No digest found in MSO for namespace '%s', digestID %d", namespace, digestID));

        Object expectedDigestObj = expectedDigestPair.getValue();
        if (expectedDigestObj instanceof CBORByteArray) {
            return ((CBORByteArray) expectedDigestObj).getValue();
        } else if (expectedDigestObj instanceof byte[]) {
            return (byte[]) expectedDigestObj;
        } else {
            throw new IllegalArgumentException(
                "Expected digest to be byte array, got: " + expectedDigestObj.getClass());
        }
    }

    /**
     * Verify that computed digest matches expected digest.
     *
     * @param expectedDigest The expected digest from MSO
     * @param actualDigest The computed digest
     * @param namespace The namespace name (for error messages)
     * @param digestID The digestID (for error messages)
     * @throws IllegalArgumentException if digests don't match
     */
    public static void assertDigestMatches(byte[] expectedDigest, byte[] actualDigest,
                                           String namespace, int digestID) {
        boolean matches = Arrays.equals(expectedDigest, actualDigest);
        Assert.isTrue(matches,
            String.format("Digest mismatch for namespace '%s', digestID %d. " +
                "Expected: %s, Actual: %s",
                namespace, digestID,
                Base64.getEncoder().encodeToString(expectedDigest),
                Base64.getEncoder().encodeToString(actualDigest)));
    }

    /**
     * Verify a single IssuerSignedItem's digest.
     * This is the main verification method that:
     * 1. Encodes the item (with tag 24)
     * 2. Decodes it to extract digestID
     * 3. Gets expected digest from MSO
     * 4. Computes SHA-256 of encoded item
     * 5. Compares digests
     *
     * @param itemObj The CBOR item to verify
     * @param nsDigestsMap The valueDigests map for this namespace
     * @param sha256 MessageDigest instance for computing hashes
     * @param namespace The namespace name (for error messages)
     * @throws Exception if verification fails
     */
    public static void verifyItemDigest(CBORItem itemObj, CBORPairList nsDigestsMap,
                                        MessageDigest sha256, String namespace) throws Exception {
        // Get bytes for hashing (includes tag 24 wrapper per ISO 18013-5)
        byte[] itemBytesForDigest = itemObj.encode();

        // Decode to get digestID
        CBORPairList itemMap = decodeIssuerSignedItem(itemObj);
        int digestID = extractDigestID(itemMap);

        // Get expected digest from MSO
        byte[] expectedDigest = getExpectedDigest(nsDigestsMap, digestID, namespace);

        // Compute actual digest
        sha256.reset();
        byte[] actualDigest = sha256.digest(itemBytesForDigest);

        // Verify match
        assertDigestMatches(expectedDigest, actualDigest, namespace, digestID);
    }

}
