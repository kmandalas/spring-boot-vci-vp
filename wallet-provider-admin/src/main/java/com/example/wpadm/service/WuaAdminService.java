package com.example.wpadm.service;

import com.example.wpadm.model.DashboardStats;
import com.example.wpadm.model.WuaView;
import com.example.wpadm.repository.AuditLogRepository;
import com.example.wpadm.repository.WuaAdminRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class WuaAdminService {

    private final WuaAdminRepository wuaRepository;
    private final AuditLogRepository auditLogRepository;

    public WuaAdminService(WuaAdminRepository wuaRepository, AuditLogRepository auditLogRepository) {
        this.wuaRepository = wuaRepository;
        this.auditLogRepository = auditLogRepository;
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
        return new DashboardStats(
            wuaRepository.countTotal(),
            wuaRepository.countByStatus("ACTIVE"),
            wuaRepository.countByStatus("REVOKED"),
            wuaRepository.countExpiringSoon(7)
        );
    }

    public List<WuaView> getRecentWuas(int limit) {
        return wuaRepository.findRecentWuas(limit);
    }

    @Transactional
    public boolean revokeWua(UUID wuaId, String reason, String adminUsername) {
        int updated = wuaRepository.updateStatus(wuaId, "REVOKED");

        if (updated > 0) {
            auditLogRepository.logAction(
                adminUsername,
                "REVOKE_WUA",
                wuaId.toString(),
                "Reason: " + reason
            );
            return true;
        }
        return false;
    }
}
