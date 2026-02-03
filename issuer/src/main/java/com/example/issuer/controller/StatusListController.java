package com.example.issuer.controller;

import com.example.issuer.repository.CredentialStatusRepository;
import com.example.issuer.service.StatusListTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class StatusListController {

    private static final Logger logger = LoggerFactory.getLogger(StatusListController.class);

    private final StatusListTokenService statusListTokenService;
    private final CredentialStatusRepository credentialStatusRepository;

    public StatusListController(StatusListTokenService statusListTokenService,
                                 CredentialStatusRepository credentialStatusRepository) {
        this.statusListTokenService = statusListTokenService;
        this.credentialStatusRepository = credentialStatusRepository;
    }

    @GetMapping(value = "/.well-known/status-list/{listId}", produces = "application/statuslist+jwt")
    public ResponseEntity<String> getStatusList(@PathVariable String listId) {
        try {
            String token = statusListTokenService.generateStatusListToken(listId);
            return ResponseEntity.ok(token);
        } catch (IllegalArgumentException e) {
            logger.warn("Status list not found: {}", listId);
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("/admin/revoke")
    public ResponseEntity<Map<String, String>> revokeCredential(@RequestBody Map<String, String> request) {
        String credentialId = request.get("credentialId");
        if (credentialId == null || credentialId.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "credentialId is required"));
        }

        int updated = credentialStatusRepository.updateStatus(credentialId, "REVOKED");
        if (updated == 0) {
            return ResponseEntity.notFound().build();
        }

        logger.info("Revoked credential: {}", credentialId);
        return ResponseEntity.ok(Map.of("status", "revoked", "credentialId", credentialId));
    }
}
