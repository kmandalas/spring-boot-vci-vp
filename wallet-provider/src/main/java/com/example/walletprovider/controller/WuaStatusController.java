package com.example.walletprovider.controller;

import com.example.walletprovider.model.WalletUnitAttestation;
import com.example.walletprovider.repository.WuaRepository;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/wp/wua")
public class WuaStatusController {

    private final WuaRepository wuaRepository;

    public WuaStatusController(WuaRepository wuaRepository) {
        this.wuaRepository = wuaRepository;
    }

    @GetMapping(value = "/status/{wuaId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getWuaStatus(@PathVariable UUID wuaId) {
        Optional<WalletUnitAttestation> wuaOpt = wuaRepository.findById(wuaId);

        if (wuaOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        WalletUnitAttestation wua = wuaOpt.get();

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("wua_id", wua.wuaId().toString());
        response.put("status", wua.status().toLowerCase());
        response.put("wscd_type", wua.wscdType());
        response.put("wscd_security_level", wua.wscdSecurityLevel());
        response.put("issued_at", wua.issuedAt().toString());
        response.put("expires_at", wua.expiresAt().toString());

        return ResponseEntity.ok(response);
    }
}
