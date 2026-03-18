package com.example.wpadm.client;

import com.example.wpadm.client.dto.EventsResponse;
import com.example.wpadm.client.dto.OutboxEventDto;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

import static com.example.wpadm.util.JdbcUtil.toOffsetDateTime;

import java.time.Instant;
import java.util.UUID;

@Component
public class WalletProviderEventPoller {

    private static final Logger log = LoggerFactory.getLogger(WalletProviderEventPoller.class);

    private final WalletProviderAdminClient client;
    private final JdbcClient jdbcClient;
    private final ObjectMapper objectMapper;

    public WalletProviderEventPoller(WalletProviderAdminClient client, JdbcClient jdbcClient,
                                     ObjectMapper objectMapper) {
        this.client = client;
        this.jdbcClient = jdbcClient;
        this.objectMapper = objectMapper;
    }

    @Scheduled(fixedDelayString = "${wallet-provider.poll-interval-seconds:5}000")
    public void pollEvents() {
        try {
            long cursor = readCursor();
            EventsResponse response = client.pollEvents(cursor, 100);

            if (response == null || response.events() == null || response.events().isEmpty()) {
                return;
            }

            log.debug("📥 Polled {} events from wallet-provider (since={})", response.events().size(), cursor);

            for (OutboxEventDto event : response.events()) {
                processEvent(event);
            }

            // Advance cursor to the last event's sequential id
            long lastEventId = response.events().getLast().id();
            advanceCursor(lastEventId);

        } catch (Exception e) {
            log.warn("⚠️ Event polling failed (will retry next cycle): {}", e.getMessage());
        }
    }

    @Transactional
    protected void processEvent(OutboxEventDto event) {
        try {
            switch (event.type()) {
                case "WuaIssued" -> processWuaIssued(event);
                case "WuaRevoked" -> processWuaRevoked(event);
                default -> log.warn("⚠️ Unknown event type: {}", event.type());
            }
        } catch (Exception e) {
            log.error("❌ Failed to process event: type={}, key={}", event.type(), event.key(), e);
        }
    }

    private void processWuaIssued(OutboxEventDto event) {
        var payload = parsePayload(event.payload(), WuaIssuedPayload.class);
        if (payload == null) return;

        jdbcClient.sql("""
                INSERT INTO wua_projections
                (wua_id, wallet_public_key_thumbprint, status, wscd_type, wscd_security_level,
                 issued_at, expires_at, status_list_id, status_list_idx, projected_at)
                VALUES (:wuaId, :thumbprint, :status, :wscdType, :wscdSecurityLevel,
                        :issuedAt, :expiresAt, :statusListId, :statusListIdx, :projectedAt)
                ON CONFLICT (wua_id) DO UPDATE SET
                    status = EXCLUDED.status, projected_at = EXCLUDED.projected_at
                """)
                .param("wuaId", payload.wuaId())
                .param("thumbprint", payload.walletPublicKeyThumbprint())
                .param("status", payload.status())
                .param("wscdType", payload.wscdType())
                .param("wscdSecurityLevel", payload.wscdSecurityLevel())
                .param("issuedAt", toOffsetDateTime(payload.issuedAt()))
                .param("expiresAt", toOffsetDateTime(payload.expiresAt()))
                .param("statusListId", payload.statusListId())
                .param("statusListIdx", payload.statusListIdx())
                .param("projectedAt", toOffsetDateTime(Instant.now()))
                .update();

        jdbcClient.sql("""
                UPDATE wua_stats SET
                    total_count = total_count + 1,
                    active_count = active_count + 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = 1
                """)
                .update();

        log.debug("📋 Projected WuaIssued: {}", payload.wuaId());
    }

    private void processWuaRevoked(OutboxEventDto event) {
        var payload = parsePayload(event.payload(), WuaRevokedPayload.class);
        if (payload == null) return;

        int updated = jdbcClient.sql("""
                UPDATE wua_projections SET status = 'REVOKED', projected_at = :projectedAt
                WHERE wua_id = :wuaId AND status = 'ACTIVE'
                """)
                .param("wuaId", payload.wuaId())
                .param("projectedAt", toOffsetDateTime(Instant.now()))
                .update();

        if (updated > 0) {
            jdbcClient.sql("""
                    UPDATE wua_stats SET
                        active_count = active_count - 1,
                        revoked_count = revoked_count + 1,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = 1
                    """)
                    .update();
        }

        log.debug("🔴 Projected WuaRevoked: {}", payload.wuaId());
    }

    private long readCursor() {
        return jdbcClient.sql("SELECT last_event_id FROM event_cursor WHERE id = 1")
                .query(Long.class)
                .single();
    }

    private void advanceCursor(long lastEventId) {
        jdbcClient.sql("UPDATE event_cursor SET last_event_id = :lastEventId, updated_at = CURRENT_TIMESTAMP WHERE id = 1")
                .param("lastEventId", lastEventId)
                .update();
    }

    private <T> T parsePayload(String json, Class<T> type) {
        try {
            return objectMapper.readValue(json, type);
        } catch (Exception e) {
            log.error("❌ Failed to parse event payload as {}: {}", type.getSimpleName(), e.getMessage());
            return null;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record WuaIssuedPayload(
            UUID wuaId,
            String walletPublicKeyThumbprint,
            String status,
            String wscdType,
            String wscdSecurityLevel,
            Instant issuedAt,
            Instant expiresAt,
            String statusListId,
            Integer statusListIdx
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record WuaRevokedPayload(
            UUID wuaId,
            String reason,
            String adminUser,
            Instant revokedAt
    ) {}
}
