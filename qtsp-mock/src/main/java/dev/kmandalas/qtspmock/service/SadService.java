package dev.kmandalas.qtspmock.service;

import dev.kmandalas.qtspmock.config.QtspProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SadService {

    private static final Logger logger = LoggerFactory.getLogger(SadService.class);

    private final QtspProperties qtspProperties;
    private final ConcurrentHashMap<String, SadEntry> activeSads = new ConcurrentHashMap<>();

    public SadService(QtspProperties qtspProperties) {
        this.qtspProperties = qtspProperties;
    }

    public String issueSad(String credentialId) {
        String sad = UUID.randomUUID().toString();
        Instant expiresAt = Instant.now().plusSeconds(qtspProperties.getSadTtlSeconds());
        activeSads.put(sad, new SadEntry(credentialId, expiresAt));
        logger.info("🎫 Issued SAD for credential {}, expires {}", credentialId, expiresAt);
        return sad;
    }

    /**
     * Validates and consumes a SAD (single-use).
     * Returns the credentialId if valid, null otherwise.
     */
    public String validateAndConsume(String sad, String credentialId) {
        SadEntry entry = activeSads.remove(sad);
        if (entry == null) {
            logger.warn("⚠️ SAD not found or already used: {}", sad);
            return null;
        }
        if (Instant.now().isAfter(entry.expiresAt())) {
            logger.warn("⚠️ SAD expired: {}", sad);
            return null;
        }
        if (!entry.credentialId().equals(credentialId)) {
            logger.warn("⚠️ SAD credential mismatch: expected {}, got {}", entry.credentialId(), credentialId);
            return null;
        }
        logger.info("✅ SAD consumed for credential {}", credentialId);
        return entry.credentialId();
    }

    public long getTtlSeconds() {
        return qtspProperties.getSadTtlSeconds();
    }

    private record SadEntry(String credentialId, Instant expiresAt) {}

}
