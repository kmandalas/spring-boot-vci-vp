package com.example.wpadm.service;

import com.example.wpadm.client.WalletProviderAdminClient;
import com.example.wpadm.client.dto.RevocationResultDto;
import com.example.wpadm.model.DashboardStats;
import com.example.wpadm.model.WuaView;
import com.example.wpadm.repository.AuditLogRepository;
import com.example.wpadm.repository.WuaAdminRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;

import static com.example.wpadm.util.JdbcUtil.toOffsetDateTime;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class WuaAdminService {

    private static final Logger log = LoggerFactory.getLogger(WuaAdminService.class);

    private final WuaAdminRepository wuaRepository;
    private final AuditLogRepository auditLogRepository;
    private final WalletProviderAdminClient walletProviderClient;
    private final JdbcClient jdbcClient;

    public WuaAdminService(WuaAdminRepository wuaRepository, AuditLogRepository auditLogRepository,
                           WalletProviderAdminClient walletProviderClient, JdbcClient jdbcClient) {
        this.wuaRepository = wuaRepository;
        this.auditLogRepository = auditLogRepository;
        this.walletProviderClient = walletProviderClient;
        this.jdbcClient = jdbcClient;
    }

    public List<WuaView> findWuas(String status, String wscdType, String search, int page, int size) {
        return wuaRepository.findAll(status, wscdType, search, size, page * size);
    }

    public long countWuas(String status, String wscdType, String search) {
        return wuaRepository.countAll(status, wscdType, search);
    }

    public Optional<WuaView> findById(UUID wuaId) {
        return wuaRepository.findById(wuaId);
    }

    public List<String> getDistinctWscdTypes() {
        return wuaRepository.findDistinctWscdTypes();
    }

    public DashboardStats getDashboardStats() {
        // Read from pre-computed stats table (O(1) instead of counting)
        var stats = jdbcClient.sql("SELECT total_count, active_count, revoked_count FROM wua_stats WHERE id = 1")
                .query((rs, _) -> new DashboardStats(
                        rs.getLong("total_count"),
                        rs.getLong("active_count"),
                        rs.getLong("revoked_count"),
                        countExpiringSoon(7)
                ))
                .optional();

        return stats.orElse(new DashboardStats(0, 0, 0, 0));
    }

    public List<WuaView> getRecentWuas(int limit) {
        return wuaRepository.findRecentWuas(limit);
    }

    /**
     * Revokes a WUA via synchronous REST call to wallet-provider,
     * then logs the action locally for audit.
     */
    public boolean revokeWua(UUID wuaId, String reason, String adminUsername) {
        try {
            RevocationResultDto result = walletProviderClient.revokeWua(wuaId, reason, adminUsername);

            if ("REVOKED".equals(result.status())) {
                auditLogRepository.logAction(
                        adminUsername,
                        "REVOKE_WUA",
                        wuaId.toString(),
                        "Reason: " + reason
                );
                log.info("🔴 WUA revoked via wallet-provider: {}", wuaId);
                return true;
            } else {
                log.warn("⚠️ Revocation returned non-success: {}", result.message());
                return false;
            }
        } catch (Exception e) {
            log.error("❌ Failed to revoke WUA via wallet-provider: {}", e.getMessage());
            throw new WalletProviderUnavailableException("Wallet provider is unavailable: " + e.getMessage(), e);
        }
    }

    private long countExpiringSoon(int days) {
        Instant threshold = Instant.now().plus(days, ChronoUnit.DAYS);
        return jdbcClient.sql("""
            SELECT COUNT(*) FROM wua_projections
            WHERE status = 'ACTIVE' AND expires_at <= :threshold
            """)
            .param("threshold", toOffsetDateTime(threshold))
            .query(Long.class)
            .single();
    }
}
