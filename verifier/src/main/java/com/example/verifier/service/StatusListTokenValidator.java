package com.example.verifier.service;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.Map;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

@Component
public class StatusListTokenValidator {

    private static final Logger logger = LoggerFactory.getLogger(StatusListTokenValidator.class);

    private final RestTemplate restTemplate;

    public StatusListTokenValidator() {
        this.restTemplate = new RestTemplate();
    }

    public sealed interface StatusCheckResult {
        record Skipped() implements StatusCheckResult {}
        record Valid() implements StatusCheckResult {}
        record Revoked() implements StatusCheckResult {}
        record Error(String message) implements StatusCheckResult {}
    }

    /**
     * Check credential revocation status using the Token Status List mechanism.
     *
     * @param credentialClaims the claims from the credential JWT
     * @return the result of the status check
     */
    @SuppressWarnings("unchecked")
    public StatusCheckResult checkStatus(JWTClaimsSet credentialClaims) {
        try {
            // Extract status claim
            Map<String, Object> statusClaim = (Map<String, Object>) credentialClaims.getClaim("status");
            if (statusClaim == null) {
                return new StatusCheckResult.Skipped();
            }

            Map<String, Object> statusList = (Map<String, Object>) statusClaim.get("status_list");
            if (statusList == null) {
                return new StatusCheckResult.Skipped();
            }

            Object idxObj = statusList.get("idx");
            String uri = (String) statusList.get("uri");
            if (idxObj == null || uri == null) {
                return new StatusCheckResult.Error("Incomplete status claim: missing idx or uri");
            }

            int idx = ((Number) idxObj).intValue();
            logger.debug("Checking credential status: idx={}, uri={}", idx, uri);

            // Fetch the status list JWT
            String statusListJwt = restTemplate.getForObject(uri, String.class);
            if (statusListJwt == null || statusListJwt.isBlank()) {
                return new StatusCheckResult.Error("Empty response from status list endpoint: " + uri);
            }

            // Parse the status list JWT (skip signature verification, matching EU ref impl default)
            SignedJWT statusListToken = SignedJWT.parse(statusListJwt.trim());
            JWTClaimsSet statusListClaims = statusListToken.getJWTClaimsSet();

            Map<String, Object> statusListPayload = (Map<String, Object>) statusListClaims.getClaim("status_list");
            if (statusListPayload == null) {
                return new StatusCheckResult.Error("No status_list claim in status list token");
            }

            int bits = ((Number) statusListPayload.get("bits")).intValue();
            String lst = (String) statusListPayload.get("lst");

            // Base64url-decode and DEFLATE-decompress
            byte[] compressed = Base64.getUrlDecoder().decode(lst);
            byte[] bitstring = decompress(compressed);

            // Read the status value at the given index
            int value = getBitValue(bitstring, idx, bits);

            if (value != 0) {
                logger.warn("⛔ Credential is revoked (status index {}, value {})", idx, value);
                return new StatusCheckResult.Revoked();
            }

            logger.debug("Credential status valid (index {})", idx);
            return new StatusCheckResult.Valid();

        } catch (Exception e) {
            logger.error("❌ Status check failed", e);
            return new StatusCheckResult.Error("Status check failed: " + e.getMessage());
        }
    }

    /**
     * Decompress DEFLATE-compressed data.
     */
    byte[] decompress(byte[] compressed) throws DataFormatException {
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(compressed);
            byte[] buffer = new byte[compressed.length * 10];
            int totalSize = 0;
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer, totalSize, buffer.length - totalSize);
                if (count == 0 && inflater.needsInput()) {
                    break;
                }
                totalSize += count;
                if (totalSize == buffer.length) {
                    byte[] newBuffer = new byte[buffer.length * 2];
                    System.arraycopy(buffer, 0, newBuffer, 0, totalSize);
                    buffer = newBuffer;
                }
            }
            byte[] result = new byte[totalSize];
            System.arraycopy(buffer, 0, result, 0, totalSize);
            return result;
        } finally {
            inflater.end();
        }
    }

    /**
     * Read the value at the given index from the bitstring using LSB-first packing.
     * Mirrors the issuer's setBitValue logic.
     */
    int getBitValue(byte[] bitstring, int idx, int bits) {
        int bitPosition = idx * bits;
        int byteIndex = bitPosition / 8;
        int bitOffset = bitPosition % 8;

        if (byteIndex >= bitstring.length) {
            return 0;
        }

        return (bitstring[byteIndex] >> bitOffset) & ((1 << bits) - 1);
    }

}
