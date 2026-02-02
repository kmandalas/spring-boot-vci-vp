package com.example.walletprovider.controller;

import com.example.walletprovider.service.WpSigningService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/wp/.well-known")
public class WpPublicKeyController {

    private final WpSigningService wpSigningService;

    public WpPublicKeyController(WpSigningService wpSigningService) {
        this.wpSigningService = wpSigningService;
    }

    @GetMapping(value = "/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getPublicKey() {
        return ResponseEntity.ok(wpSigningService.getJwksResponse());
    }

}
