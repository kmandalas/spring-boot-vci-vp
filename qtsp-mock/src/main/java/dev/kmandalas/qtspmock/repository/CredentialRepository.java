package dev.kmandalas.qtspmock.repository;

import dev.kmandalas.qtspmock.util.JdbcUtil;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public class CredentialRepository {

    private final JdbcClient jdbcClient;

    public CredentialRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public record PersistedCredential(
            String credentialId,
            String userId,
            byte[] privateKey,
            byte[] publicKey,
            byte[] certificate,
            Instant createdAt
    ) {}

    public void save(PersistedCredential credential) {
        jdbcClient.sql("""
                INSERT INTO qtsp_credentials (credential_id, user_id, private_key, public_key, certificate, created_at)
                VALUES (:credentialId, :userId, :privateKey, :publicKey, :certificate, :createdAt)
                ON CONFLICT (credential_id) DO NOTHING
                """)
                .param("credentialId", credential.credentialId())
                .param("userId", credential.userId())
                .param("privateKey", credential.privateKey())
                .param("publicKey", credential.publicKey())
                .param("certificate", credential.certificate())
                .param("createdAt", JdbcUtil.toOffsetDateTime(credential.createdAt()))
                .update();
    }

    public Optional<PersistedCredential> findByCredentialId(String credentialId) {
        return jdbcClient.sql("SELECT * FROM qtsp_credentials WHERE credential_id = :credentialId")
                .param("credentialId", credentialId)
                .query((rs, _) -> new PersistedCredential(
                        rs.getString("credential_id"),
                        rs.getString("user_id"),
                        rs.getBytes("private_key"),
                        rs.getBytes("public_key"),
                        rs.getBytes("certificate"),
                        rs.getTimestamp("created_at").toInstant()
                ))
                .optional();
    }

    public List<PersistedCredential> findByUserId(String userId) {
        return jdbcClient.sql("SELECT * FROM qtsp_credentials WHERE user_id = :userId")
                .param("userId", userId)
                .query((rs, _) -> new PersistedCredential(
                        rs.getString("credential_id"),
                        rs.getString("user_id"),
                        rs.getBytes("private_key"),
                        rs.getBytes("public_key"),
                        rs.getBytes("certificate"),
                        rs.getTimestamp("created_at").toInstant()
                ))
                .list();
    }

    public List<PersistedCredential> findAll() {
        return jdbcClient.sql("SELECT * FROM qtsp_credentials ORDER BY created_at")
                .query((rs, _) -> new PersistedCredential(
                        rs.getString("credential_id"),
                        rs.getString("user_id"),
                        rs.getBytes("private_key"),
                        rs.getBytes("public_key"),
                        rs.getBytes("certificate"),
                        rs.getTimestamp("created_at").toInstant()
                ))
                .list();
    }
}
