package com.example.issuer.controller;

import com.example.issuer.service.IssuerSigningService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/.well-known")
public class PublicKeyController {

    private final IssuerSigningService issuerSigningService;

    public PublicKeyController(IssuerSigningService issuerSigningService) {
        this.issuerSigningService = issuerSigningService;
    }

    @GetMapping("/jwks.json")
    public ResponseEntity<Map<String, Object>> getPublicKey() {
        return ResponseEntity.ok(issuerSigningService.getJwksResponse());
    }

}

