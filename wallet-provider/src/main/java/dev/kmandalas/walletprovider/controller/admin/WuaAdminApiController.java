package dev.kmandalas.walletprovider.controller.admin;

import dev.kmandalas.walletprovider.controller.admin.dto.OutboxEventDto;
import dev.kmandalas.walletprovider.controller.admin.dto.RevocationRequest;
import dev.kmandalas.walletprovider.controller.admin.dto.RevocationResultDto;
import dev.kmandalas.walletprovider.service.WuaAdminService;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/wp/admin/api/v1")
public class WuaAdminApiController {

    private final JdbcClient jdbcClient;
    private final WuaAdminService wuaAdminService;

    public WuaAdminApiController(JdbcClient jdbcClient, WuaAdminService wuaAdminService) {
        this.jdbcClient = jdbcClient;
        this.wuaAdminService = wuaAdminService;
    }

    @GetMapping("/events")
    public ResponseEntity<Map<String, Object>> pollEvents(
            @RequestParam(defaultValue = "0") long since,
            @RequestParam(defaultValue = "100") int limit) {

        List<OutboxEventDto> events = jdbcClient.sql("""
                SELECT id, event_type, event_key, payload, created_at
                FROM wua_events
                WHERE id > :since
                ORDER BY id ASC
                LIMIT :limit
                """)
                .param("since", since)
                .param("limit", limit)
                .query((rs, _) -> new OutboxEventDto(
                        rs.getLong("id"),
                        rs.getString("event_type"),
                        rs.getString("event_key"),
                        rs.getString("payload"),
                        rs.getTimestamp("created_at").toInstant()
                ))
                .list();

        return ResponseEntity.ok(Map.of("events", events));
    }

    @PostMapping("/wuas/{wuaId}/revoke")
    public ResponseEntity<RevocationResultDto> revokeWua(
            @PathVariable UUID wuaId,
            @RequestBody RevocationRequest request) {

        boolean success = wuaAdminService.revokeWua(wuaId, request.reason(), request.adminUser());

        if (success) {
            return ResponseEntity.ok(new RevocationResultDto(wuaId, "REVOKED", "WUA revoked successfully"));
        } else {
            return ResponseEntity.badRequest()
                    .body(new RevocationResultDto(wuaId, "FAILED", "WUA not found or already revoked"));
        }
    }
}
