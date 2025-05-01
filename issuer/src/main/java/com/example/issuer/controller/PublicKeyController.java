package com.example.issuer.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/.well-known")
public class PublicKeyController {

    @Value("classpath:/issuer_key.json")
    private Resource issuerKeyResource;

    @GetMapping("/jwks.json")
    public ResponseEntity<Map<String, Object>> getPublicKey() throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> keypair = objectMapper.readValue(issuerKeyResource.getInputStream(), new TypeReference<>() {});

        // Remove the private key (`d`) before exposing it
        keypair.remove("d");

        // Wrap in a JWKS response format
        Map<String, Object> jwksResponse = Map.of("keys", List.of(keypair));
        return ResponseEntity.ok(jwksResponse);
    }

}

