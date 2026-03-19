package dev.kmandalas.walletprovider.service;

import dev.kmandalas.walletprovider.event.WuaRevokedEvent;
import dev.kmandalas.walletprovider.model.WalletUnitAttestation;
import dev.kmandalas.walletprovider.repository.WuaRepository;
import io.namastack.outbox.Outbox;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class WuaAdminService {

    private static final Logger log = LoggerFactory.getLogger(WuaAdminService.class);

    private final WuaRepository wuaRepository;
    private final JdbcClient jdbcClient;
    private final Outbox outbox;
    private final StatusListTokenService statusListTokenService;

    public WuaAdminService(WuaRepository wuaRepository, JdbcClient jdbcClient,
                           Outbox outbox, StatusListTokenService statusListTokenService) {
        this.wuaRepository = wuaRepository;
        this.jdbcClient = jdbcClient;
        this.outbox = outbox;
        this.statusListTokenService = statusListTokenService;
    }

    @Transactional
    public boolean revokeWua(UUID wuaId, String reason, String adminUser) {
        var wuaOpt = wuaRepository.findById(wuaId);
        if (wuaOpt.isEmpty()) {
            log.warn("🚫 Revocation failed: WUA not found: {}", wuaId);
            return false;
        }

        WalletUnitAttestation wua = wuaOpt.get();
        if (WalletUnitAttestation.STATUS_REVOKED.equals(wua.status())) {
            log.warn("🚫 WUA already revoked: {}", wuaId);
            return false;
        }

        // Update status in DB
        jdbcClient.sql("UPDATE wallet_unit_attestations SET status = :status WHERE wua_id = :wuaId")
                .param("status", WalletUnitAttestation.STATUS_REVOKED)
                .param("wuaId", wuaId)
                .update();

        // Publish revocation event to outbox (same transaction)
        outbox.schedule(
                new WuaRevokedEvent(wuaId, reason, adminUser, Instant.now()),
                wuaId.toString()
        );

        log.info("🔴 WUA revoked: id={}, reason={}, by={}", wuaId, reason, adminUser);
        return true;
    }
}
