package com.example.wpadm.repository;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.UUID;

@Repository
public class AuditLogRepository {

    private final JdbcClient jdbcClient;

    public AuditLogRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public void logAction(String username, String action, String targetId, String details) {
        jdbcClient.sql("""
            INSERT INTO admin_audit_log (id, username, action, target_id, details, created_at)
            VALUES (:id, :username, :action, :targetId, :details, :createdAt)
            """)
            .param("id", UUID.randomUUID())
            .param("username", username)
            .param("action", action)
            .param("targetId", targetId)
            .param("details", details)
            .param("createdAt", Instant.now())
            .update();
    }
}
