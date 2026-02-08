package com.example.verifier.util;

import com.authlete.cbor.*;
import com.authlete.cose.COSESign1;

import java.time.Instant;

/**
 * General CBOR parsing utilities for mDoc verification.
 * Handles date/time parsing, MSO extraction, and CBOR type conversions.
 *
 * This helper class complements MDocDigestHelper by providing general-purpose
 * CBOR utilities that are not specific to digest verification.
 */
public class MDocCBORHelper {

    /**
     * Parse an Instant from a CBOR date/time value.
     *
     * CBOR dates can be encoded as:
     * - Tagged item (tag 0): Numeric timestamp (seconds since epoch)
     * - Tagged item (tag 1): String timestamp (ISO 8601)
     * - tstr: ISO 8601 string
     * - Number: Seconds since epoch
     *
     * @param cborValue The CBOR value to parse
     * @return Instant representing the date/time
     * @throws IllegalArgumentException if the format is unsupported
     */
    public static Instant parseInstantFromCBOR(Object cborValue) {
        // Recursively unwrap nested tagged items (sometimes dates are double-wrapped)
        while (cborValue instanceof CBORTaggedItem tagged) {
            Object tagContent = tagged.getTagContent();
            int tagNumber = tagged.getTagNumber().intValue();

            // Tag 0: numeric date (seconds or milliseconds since epoch)
            if (tagNumber == 0) {
                if (tagContent instanceof CBORLong) {
                    long epochSeconds = ((CBORLong) tagContent).getValue();
                    return Instant.ofEpochSecond(epochSeconds);
                } else if (tagContent instanceof CBORInteger) {
                    long epochSeconds = ((CBORInteger) tagContent).getValue();
                    return Instant.ofEpochSecond(epochSeconds);
                } else if (tagContent instanceof CBORDouble) {
                    double epochSecondsDouble = ((CBORDouble) tagContent).getValue();
                    long epochSeconds = (long) epochSecondsDouble;
                    return Instant.ofEpochSecond(epochSeconds);
                }
            }

            // Tag 1: string date (ISO 8601)
            if (tagNumber == 1 && tagContent instanceof CBORString) {
                String dateStr = ((CBORString) tagContent).getValue();
                return Instant.parse(dateStr);
            }

            // If tag content is another tagged item, unwrap it
            if (tagContent instanceof CBORTaggedItem) {
                cborValue = tagContent;
                continue;
            }

            // If tag content is a string, try to parse as ISO 8601
            if (tagContent instanceof CBORString) {
                String dateStr = ((CBORString) tagContent).getValue();
                return Instant.parse(dateStr);
            }

            break;
        }

        // Handle direct string (tstr)
        if (cborValue instanceof CBORString) {
            String dateStr = ((CBORString) cborValue).getValue();
            return Instant.parse(dateStr);
        }

        // Handle direct numeric value (seconds since epoch)
        if (cborValue instanceof CBORLong) {
            long epochSeconds = ((CBORLong) cborValue).getValue();
            return Instant.ofEpochSecond(epochSeconds);
        }

        if (cborValue instanceof CBORInteger) {
            long epochSeconds = ((CBORInteger) cborValue).getValue();
            return Instant.ofEpochSecond(epochSeconds);
        }

        if (cborValue instanceof CBORDouble) {
            double epochSecondsDouble = ((CBORDouble) cborValue).getValue();
            long epochSeconds = (long) epochSecondsDouble;
            return Instant.ofEpochSecond(epochSeconds);
        }

        throw new IllegalArgumentException("Unsupported CBOR date format: " + cborValue.getClass().getName());
    }

    /**
     * Parse the MSO (Mobile Security Object) from IssuerAuth payload.
     *
     * Handles CBOR tag unwrapping and nested byte array decoding.
     *
     * Note: Returns CBORPairList instead of MobileSecurityObject because CBOR decoding
     * produces generic CBORPairList instances. While MobileSecurityObject extends CBORPairList,
     * we cannot cast the decoded result (Java ClassCastException). Authlete's MobileSecurityObject
     * is primarily used for encoding (issuer side), not decoding (verifier side).
     *
     * @param issuerAuth the COSESign1 containing the MSO as payload
     * @return the parsed MSO as CBORPairList (semantically a MobileSecurityObject)
     * @throws Exception if parsing fails
     */
    public static CBORPairList parseMSO(COSESign1 issuerAuth) throws Exception {
        // Get the payload (MSO) from IssuerAuth
        // COSESign1.getPayload() returns CBORItem, we need to get the actual bytes and decode
        CBORItem msoPayloadItem = issuerAuth.getPayload();

        // The payload might be a CBORByteArray, we need to get its value and decode it
        byte[] msoBytes;
        if (msoPayloadItem instanceof CBORByteArray) {
            msoBytes = ((CBORByteArray) msoPayloadItem).getValue();
        } else {
            msoBytes = msoPayloadItem.encode();
        }

        // Decode MSO CBOR - it might be tagged (CBOR tag 24 for embedded CBOR)
        CBORDecoder msoDecoder = new CBORDecoder(msoBytes);
        Object msoRawObj = msoDecoder.next();

        // Unwrap if it's a tagged item (tag 24 means embedded CBOR)
        Object msoUnwrapped = msoRawObj;
        if (msoRawObj instanceof CBORTaggedItem tagged) {
            msoUnwrapped = tagged.getTagContent();
        }

        // If still a ByteArray, decode it again
        if (msoUnwrapped instanceof CBORByteArray) {
            byte[] innerBytes = ((CBORByteArray) msoUnwrapped).getValue();
            CBORDecoder innerDecoder = new CBORDecoder(innerBytes);
            msoUnwrapped = innerDecoder.next();
        }

        return (CBORPairList) msoUnwrapped;
    }

}
