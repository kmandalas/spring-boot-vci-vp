package com.example.walletprovider.model;

import java.time.Instant;

/**
 * Represents a Token Status List as defined in IETF draft-ietf-oauth-status-list.
 * Each status list contains a bitstring where each bit (or group of bits) represents
 * the revocation status of a credential.
 *
 * @param id         Unique identifier for this status list (UUID)
 * @param bits       Number of bits per status entry (1, 2, 4, or 8)
 * @param maxEntries Maximum number of entries this list can hold
 * @param createdAt  When this status list was created
 */
public record StatusList(
        String id,
        int bits,
        int maxEntries,
        Instant createdAt
) {
    public static final int DEFAULT_BITS = 1;
    public static final int DEFAULT_MAX_ENTRIES = 1000;

    /**
     * Calculate the byte array size needed for this status list.
     */
    public int getByteSize() {
        return (maxEntries * bits + 7) / 8;
    }
}
