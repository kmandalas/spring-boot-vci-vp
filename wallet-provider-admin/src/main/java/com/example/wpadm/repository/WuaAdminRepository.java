package com.example.wpadm.repository;

import com.example.wpadm.model.WuaView;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.util.*;

@Repository
public class WuaAdminRepository {

    private final JdbcClient jdbcClient;

    public WuaAdminRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public List<WuaView> findAll(String status, String wscdType, String search, int limit, int offset) {
        StringBuilder sql = new StringBuilder("""
            SELECT wua_id, wallet_public_key_thumbprint, status, wscd_type,
                   wscd_security_level, issued_at, expires_at, status_list_id, status_list_idx
            FROM wua_projections WHERE 1=1
            """);

        Map<String, Object> params = new HashMap<>();

        if (status != null && !status.isEmpty()) {
            sql.append(" AND status = :status");
            params.put("status", status);
        }
        if (wscdType != null && !wscdType.isEmpty()) {
            sql.append(" AND wscd_type = :wscdType");
            params.put("wscdType", wscdType);
        }
        if (search != null && !search.isEmpty()) {
            sql.append(" AND (wallet_public_key_thumbprint ILIKE :search OR CAST(wua_id AS VARCHAR) ILIKE :search)");
            params.put("search", "%" + search + "%");
        }

        sql.append(" ORDER BY issued_at DESC LIMIT :limit OFFSET :offset");
        params.put("limit", limit);
        params.put("offset", offset);

        JdbcClient.StatementSpec spec = jdbcClient.sql(sql.toString());
        params.forEach(spec::param);

        return spec.query(WuaView.class).list();
    }

    public long countAll(String status, String wscdType, String search) {
        StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM wua_projections WHERE 1=1");

        Map<String, Object> params = new HashMap<>();

        if (status != null && !status.isEmpty()) {
            sql.append(" AND status = :status");
            params.put("status", status);
        }
        if (wscdType != null && !wscdType.isEmpty()) {
            sql.append(" AND wscd_type = :wscdType");
            params.put("wscdType", wscdType);
        }
        if (search != null && !search.isEmpty()) {
            sql.append(" AND (wallet_public_key_thumbprint ILIKE :search OR CAST(wua_id AS VARCHAR) ILIKE :search)");
            params.put("search", "%" + search + "%");
        }

        JdbcClient.StatementSpec spec = jdbcClient.sql(sql.toString());
        params.forEach(spec::param);

        return spec.query(Long.class).single();
    }

    public Optional<WuaView> findById(UUID wuaId) {
        return jdbcClient.sql("""
            SELECT wua_id, wallet_public_key_thumbprint, status, wscd_type,
                   wscd_security_level, issued_at, expires_at, status_list_id, status_list_idx
            FROM wua_projections WHERE wua_id = :wuaId
            """)
            .param("wuaId", wuaId)
            .query(WuaView.class)
            .optional();
    }

    public List<String> findDistinctWscdTypes() {
        return jdbcClient.sql("SELECT DISTINCT wscd_type FROM wua_projections WHERE wscd_type IS NOT NULL ORDER BY wscd_type")
            .query(String.class)
            .list();
    }

    public List<WuaView> findRecentWuas(int limit) {
        return jdbcClient.sql("""
            SELECT wua_id, wallet_public_key_thumbprint, status, wscd_type,
                   wscd_security_level, issued_at, expires_at, status_list_id, status_list_idx
            FROM wua_projections ORDER BY issued_at DESC LIMIT :limit
            """)
            .param("limit", limit)
            .query(WuaView.class)
            .list();
    }
}
