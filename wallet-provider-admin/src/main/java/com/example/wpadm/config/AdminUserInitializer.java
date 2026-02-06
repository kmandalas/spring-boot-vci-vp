package com.example.wpadm.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.UUID;

@Component
public class AdminUserInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminUserInitializer.class);

    private final JdbcClient jdbcClient;
    private final PasswordEncoder passwordEncoder;

    public AdminUserInitializer(JdbcClient jdbcClient, PasswordEncoder passwordEncoder) {
        this.jdbcClient = jdbcClient;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        String encodedPassword = passwordEncoder.encode("admin123");

        // Check if admin user exists
        boolean exists = jdbcClient.sql("SELECT COUNT(*) FROM admin_users WHERE username = 'admin'")
            .query(Integer.class)
            .single() > 0;

        if (!exists) {
            log.info("Creating admin user with password 'admin123'");

            jdbcClient.sql("""
                INSERT INTO admin_users (id, username, password_hash, totp_secret, totp_enabled, created_at)
                VALUES (:id, :username, :passwordHash, NULL, FALSE, :createdAt)
                """)
                .param("id", UUID.randomUUID())
                .param("username", "admin")
                .param("passwordHash", encodedPassword)
                .param("createdAt", Instant.now())
                .update();

            log.info("Admin user created successfully");
        } else {
            // Reset password to ensure it works
            log.info("Admin user exists - resetting password to 'admin123'");
            jdbcClient.sql("UPDATE admin_users SET password_hash = :passwordHash WHERE username = 'admin'")
                .param("passwordHash", encodedPassword)
                .update();
        }
    }
}
