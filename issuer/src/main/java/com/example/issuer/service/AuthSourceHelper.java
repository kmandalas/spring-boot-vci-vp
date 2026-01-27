package com.example.issuer.service;

import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class AuthSourceHelper {

    public Map<String, Object> getNormalClaims(String username) {
        // Return empty - no non-standard claims for strict PDA1 compliance
        // The EU verifier may reject credentials with unexpected claims
        return Map.of();
    }

    /**
     * Returns credential holder data as a plain Map for recursive selective disclosure.
     * Each nested field will become a separate disclosure.
     */
    public Map<String, Object> getCredentialHolder(String username) {
        return switch (username) {
            case "testuser1" -> createLinkedMap(
                    "family_name", "Testopoulos",
                    "given_name", "Nikos",
                    "birth_date", "1990-01-01"
            );
            case "testuser2" -> createLinkedMap(
                    "family_name", "Validescu",
                    "given_name", "Alina",
                    "birth_date", "1985-05-15"
            );
            case "testuser3" -> createLinkedMap(
                    "family_name", "Testorov",
                    "given_name", "Tudor",
                    "birth_date", "1992-08-22"
            );
            default -> Map.of();
        };
    }

    /**
     * Returns competent institution data as a plain Map for recursive selective disclosure.
     * Each nested field will become a separate disclosure.
     */
    public Map<String, Object> getCompetentInstitution(String username) {
        return switch (username) {
            case "testuser1" -> createLinkedMap(
                    "country_code", "GR",
                    "institution_id", "EOPYY-001",
                    "institution_name", "EOPYY"
            );
            case "testuser2" -> createLinkedMap(
                    "country_code", "RO",
                    "institution_id", "CNAS-001",
                    "institution_name", "CNAS"
            );
            case "testuser3" -> createLinkedMap(
                    "country_code", "BG",
                    "institution_id", "NZOK-001",
                    "institution_name", "NZOK"
            );
            default -> Map.of();
        };
    }

    /**
     * Helper to create a LinkedHashMap with predictable key ordering.
     */
    private Map<String, Object> createLinkedMap(String k1, Object v1, String k2, Object v2, String k3, Object v3) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put(k1, v1);
        map.put(k2, v2);
        map.put(k3, v3);
        return map;
    }

}

