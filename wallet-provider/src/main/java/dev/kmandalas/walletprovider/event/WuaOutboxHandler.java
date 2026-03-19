package dev.kmandalas.walletprovider.event;

import io.namastack.outbox.annotation.OutboxHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import static dev.kmandalas.walletprovider.util.JdbcUtil.toOffsetDateTime;

import java.time.Instant;

@Component
public class WuaOutboxHandler {

    private static final Logger log = LoggerFactory.getLogger(WuaOutboxHandler.class);

    private final JdbcClient jdbcClient;
    private final ObjectMapper objectMapper;

    public WuaOutboxHandler(JdbcClient jdbcClient, ObjectMapper objectMapper) {
        this.jdbcClient = jdbcClient;
        this.objectMapper = objectMapper;
    }

    @OutboxHandler
    public void handleIssued(WuaIssuedEvent event) {
        insertEvent("WuaIssued", event.wuaId().toString(), event);
        log.debug("📤 WuaIssuedEvent written to wua_events: wuaId={}", event.wuaId());
    }

    @OutboxHandler
    public void handleRevoked(WuaRevokedEvent event) {
        insertEvent("WuaRevoked", event.wuaId().toString(), event);
        log.debug("📤 WuaRevokedEvent written to wua_events: wuaId={}", event.wuaId());
    }

    private void insertEvent(String eventType, String eventKey, Object payload) {
        try {
            String json = objectMapper.writeValueAsString(payload);
            jdbcClient.sql("""
                    INSERT INTO wua_events (event_type, event_key, payload, created_at)
                    VALUES (:eventType, :eventKey, :payload, :createdAt)
                    """)
                    .param("eventType", eventType)
                    .param("eventKey", eventKey)
                    .param("payload", json)
                    .param("createdAt", toOffsetDateTime(Instant.now()))
                    .update();
        } catch (Exception e) {
            log.error("❌ Failed to write event to wua_events: type={}, key={}", eventType, eventKey, e);
            throw new RuntimeException("Failed to persist WUA event", e);
        }
    }
}
