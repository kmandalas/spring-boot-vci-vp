package com.example.issuer.model;

import java.time.Instant;

public record StatusList(
        String id,
        int bits,
        int maxEntries,
        Instant createdAt
) {
    public int getByteSize() {
        return (maxEntries * bits + 7) / 8;
    }
}
