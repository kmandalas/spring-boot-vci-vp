package com.example.walletprovider.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.*;

@RestController
@RequestMapping("/wp")
public class WpPublicKeyController {

    @Value("classpath:/wp_key.json")
    private Resource wpKeyResource;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @GetMapping(value = "/jwks", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getPublicKey() throws IOException {
        String keyJson = new String(wpKeyResource.getInputStream().readAllBytes());
        Map<String, Object> keyMap = objectMapper.readValue(keyJson, new TypeReference<>() {});

        // Remove private key component
        keyMap.remove("d");

        Map<String, Object> jwks = new LinkedHashMap<>();
        jwks.put("keys", List.of(keyMap));

        return ResponseEntity.ok(jwks);
    }
}
