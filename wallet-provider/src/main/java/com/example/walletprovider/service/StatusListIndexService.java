package com.example.walletprovider.service;

import com.example.walletprovider.model.StatusList;
import com.example.walletprovider.repository.StatusListRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Set;

/**
 * Service for managing Token Status List indices.
 * Allocates unique, unpredictable indices per IETF draft-ietf-oauth-status-list spec.
 */
@Service
public class StatusListIndexService {

    private static final Logger logger = LoggerFactory.getLogger(StatusListIndexService.class);

    private final StatusListRepository statusListRepository;
    private final SecureRandom secureRandom;

    public StatusListIndexService(StatusListRepository statusListRepository) {
        this.statusListRepository = statusListRepository;
        this.secureRandom = new SecureRandom();
    }

    /**
     * Get or create an active status list.
     * For simplicity, we use a single status list with id "1".
     */
    public StatusList getOrCreateActiveList() {
        return statusListRepository.findById("1")
            .orElseGet(() -> {
                StatusList newList = new StatusList(
                    "1",
                    StatusList.DEFAULT_BITS,
                    StatusList.DEFAULT_MAX_ENTRIES,
                    Instant.now()
                );
                statusListRepository.save(newList);
                logger.info("Created new status list: id={}, maxEntries={}", newList.id(), newList.maxEntries());
                return newList;
            });
    }

    /**
     * Allocate a unique, unpredictable index for a new credential.
     * Per IETF spec: indices must be unique and unpredictable to prevent timing attacks.
     *
     * @param statusListId The status list to allocate from
     * @return A unique index within the status list
     * @throws IllegalStateException if the status list is full
     */
    public int allocateIndex(String statusListId) {
        StatusList statusList = statusListRepository.findById(statusListId)
            .orElseThrow(() -> new IllegalArgumentException("Status list not found: " + statusListId));

        Set<Integer> allocatedIndices = statusListRepository.getAllocatedIndices(statusListId);

        if (allocatedIndices.size() >= statusList.maxEntries()) {
            throw new IllegalStateException("Status list is full: " + statusListId);
        }

        // Generate unpredictable index using SecureRandom
        int maxAttempts = 1000;
        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            int candidateIdx = secureRandom.nextInt(statusList.maxEntries());
            if (!allocatedIndices.contains(candidateIdx)) {
                logger.debug("Allocated index {} in status list {} (attempt {})",
                    candidateIdx, statusListId, attempt + 1);
                return candidateIdx;
            }
        }

        // Fallback: linear scan for available index (should rarely happen)
        for (int i = 0; i < statusList.maxEntries(); i++) {
            if (!allocatedIndices.contains(i)) {
                logger.warn("Fallback allocation: index {} in status list {}", i, statusListId);
                return i;
            }
        }

        throw new IllegalStateException("Could not allocate index in status list: " + statusListId);
    }

}
