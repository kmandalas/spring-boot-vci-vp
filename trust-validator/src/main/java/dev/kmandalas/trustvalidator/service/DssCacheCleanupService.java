package dev.kmandalas.trustvalidator.service;

import dev.kmandalas.trustvalidator.config.TrustValidatorProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.nio.file.Path;

/**
 * Periodically cleans up the DSS file cache to avoid stale TL data.
 */
@Component
public class DssCacheCleanupService {

    private static final Logger log = LoggerFactory.getLogger(DssCacheCleanupService.class);

    private final Path cacheLocation;

    public DssCacheCleanupService(TrustValidatorProperties properties) {
        this.cacheLocation = properties.dss() != null ? properties.dss().cacheLocation() : null;
    }

    /**
     * Runs every ~24 hours (86100000 ms = 23h 55m), cleans the DSS cache directory.
     */
    @Scheduled(fixedRate = 86_100_000L, initialDelay = 0L)
    public void cleanupCache() {
        if (cacheLocation == null) return;
        log.info("Cleaning up DSS cache at {}", cacheLocation);
        var dir = cacheLocation.toFile();
        if (dir.exists()) {
            deleteRecursively(dir);
        }
    }

    private void deleteRecursively(java.io.File file) {
        if (file.isDirectory()) {
            var children = file.listFiles();
            if (children != null) {
                for (var child : children) deleteRecursively(child);
            }
        }
        file.delete();
    }
}
