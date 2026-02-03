package com.example.issuer.service;

import com.example.issuer.model.StatusList;
import com.example.issuer.repository.StatusListRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Set;

@Service
public class StatusListIndexService {

    private static final Logger logger = LoggerFactory.getLogger(StatusListIndexService.class);
    private static final String DEFAULT_LIST_ID = "1";

    private final StatusListRepository statusListRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    public StatusListIndexService(StatusListRepository statusListRepository) {
        this.statusListRepository = statusListRepository;
    }

    /**
     * Get or create the active status list with id "1".
     */
    public StatusList getOrCreateActiveList() {
        return statusListRepository.findById(DEFAULT_LIST_ID)
                .orElseGet(() -> {
                    StatusList newList = new StatusList(DEFAULT_LIST_ID, 1, 1000, Instant.now());
                    statusListRepository.save(newList);
                    logger.info("Created default status list '{}'", DEFAULT_LIST_ID);
                    return newList;
                });
    }

    /**
     * Allocate a unique index in the given status list using SecureRandom.
     * Falls back to linear scan if random collision rate is too high.
     */
    public int allocateIndex(String statusListId) {
        StatusList statusList = statusListRepository.findById(statusListId)
                .orElseThrow(() -> new IllegalStateException("Status list not found: " + statusListId));

        Set<Integer> allocatedIndices = statusListRepository.getAllocatedIndices(statusListId);
        int maxEntries = statusList.maxEntries();

        if (allocatedIndices.size() >= maxEntries) {
            throw new IllegalStateException("Status list " + statusListId + " is full");
        }

        // Try random allocation first (up to 10 attempts)
        for (int attempt = 0; attempt < 10; attempt++) {
            int candidateIndex = secureRandom.nextInt(maxEntries);
            if (!allocatedIndices.contains(candidateIndex)) {
                logger.debug("Allocated index {} in status list {} (random, attempt {})",
                        candidateIndex, statusListId, attempt + 1);
                return candidateIndex;
            }
        }

        // Fallback: linear scan for first available index
        for (int i = 0; i < maxEntries; i++) {
            if (!allocatedIndices.contains(i)) {
                logger.debug("Allocated index {} in status list {} (linear scan)", i, statusListId);
                return i;
            }
        }

        throw new IllegalStateException("Status list " + statusListId + " is full (should not reach here)");
    }
}
