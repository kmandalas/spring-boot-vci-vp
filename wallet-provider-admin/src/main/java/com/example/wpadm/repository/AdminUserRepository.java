package com.example.wpadm.repository;

import com.example.wpadm.model.AdminUser;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public class AdminUserRepository {

    private final JdbcClient jdbcClient;

    public AdminUserRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public Optional<AdminUser> findByUsername(String username) {
        return jdbcClient.sql("""
            SELECT id, username, password_hash, totp_secret, totp_enabled, created_at
            FROM admin_users WHERE username = :username
            """)
            .param("username", username)
            .query(AdminUser.class)
            .optional();
    }

    public Optional<AdminUser> findById(UUID id) {
        return jdbcClient.sql("""
            SELECT id, username, password_hash, totp_secret, totp_enabled, created_at
            FROM admin_users WHERE id = :id
            """)
            .param("id", id)
            .query(AdminUser.class)
            .optional();
    }

    public void updateTotpSecret(UUID userId, String totpSecret) {
        jdbcClient.sql("UPDATE admin_users SET totp_secret = :secret WHERE id = :id")
            .param("secret", totpSecret)
            .param("id", userId)
            .update();
    }

    public void enableTotp(UUID userId) {
        jdbcClient.sql("UPDATE admin_users SET totp_enabled = TRUE WHERE id = :id")
            .param("id", userId)
            .update();
    }

    public void disableTotp(UUID userId) {
        jdbcClient.sql("UPDATE admin_users SET totp_enabled = FALSE, totp_secret = NULL WHERE id = :id")
            .param("id", userId)
            .update();
    }
}
