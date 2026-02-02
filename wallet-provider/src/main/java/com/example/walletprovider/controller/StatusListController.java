package com.example.walletprovider.controller;

import com.example.walletprovider.service.StatusListTokenService;
import com.nimbusds.jose.JOSEException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for serving Token Status List JWTs.
 * Implements IETF draft-ietf-oauth-status-list endpoint.
 */
@RestController
@RequestMapping("/wp/.well-known")
public class StatusListController {

    private static final Logger logger = LoggerFactory.getLogger(StatusListController.class);

    private static final MediaType STATUS_LIST_JWT_MEDIA_TYPE =
        MediaType.parseMediaType("application/statuslist+jwt");

    private final StatusListTokenService statusListTokenService;

    public StatusListController(StatusListTokenService statusListTokenService) {
        this.statusListTokenService = statusListTokenService;
    }

    /**
     * Get a Status List Token for the specified list ID.
     *
     * @param listId The status list identifier
     * @return JWT with Content-Type: application/statuslist+jwt
     */
    @GetMapping(value = "/status-list/{listId}", produces = "application/statuslist+jwt")
    public ResponseEntity<String> getStatusList(@PathVariable String listId) {
        logger.debug("Status list requested: {}", listId);

        try {
            String jwt = statusListTokenService.generateStatusListToken(listId);

            return ResponseEntity.ok()
                .contentType(STATUS_LIST_JWT_MEDIA_TYPE)
                .body(jwt);

        } catch (IllegalArgumentException e) {
            logger.warn("Status list not found: {}", listId);
            return ResponseEntity.notFound().build();

        } catch (JOSEException e) {
            logger.error("Error generating status list token", e);
            return ResponseEntity.internalServerError().build();
        }
    }

}
