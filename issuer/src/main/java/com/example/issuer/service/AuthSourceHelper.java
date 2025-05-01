package com.example.issuer.service;

import com.authlete.sd.Disclosure;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
public class AuthSourceHelper {

    public Map<String, Object> getNormalClaims(String username) {
        // Example static mapping
        return switch (username) {
            case "testuser1" -> Map.of("company", "UserCorp");
            case "testuser2" -> Map.of("company", "AdminCorp");
            case "testuser3" -> Map.of("company", "GuestCorp");
            default -> Map.of("company", "Unknown");
        };
    }

    public List<Disclosure> getDisclosableClaims(String username) {
        return switch (username) {
            case "testuser1" -> List.of(
                    new Disclosure("credential_holder", "Kyriakos Mandalas"),
                    new Disclosure("nationality", "Greek"),
                    new Disclosure("competent_institution", "EOPYY")
            );
            case "testuser2" -> List.of(
                    new Disclosure("credential_holder", "Alina Adminescu"),
                    new Disclosure("nationality", "Romanian"),
                    new Disclosure("competent_institution", "Casa Nationala de Asigurari de Sanatate")
            );
            case "testuser3" -> List.of(
                    new Disclosure("credential_holder", "Tudor Iliev"),
                    new Disclosure("nationality", "Bulgarian"),
                    new Disclosure("competent_institution", "Национална здравноосигурителна каса")
            );
            default -> List.of();
        };
    }

}

