package com.example.issuer.repository;

import com.example.issuer.model.CredentialStatusEntry;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class CredentialStatusRepository {

    private final JdbcClient jdbcClient;

    public CredentialStatusRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public void save(CredentialStatusEntry entry) {
        jdbcClient.sql("INSERT INTO credential_status_entries (credential_id, username, status, status_list_id, status_list_idx, issued_at) VALUES (?, ?, ?, ?, ?, ?)")
                .param(entry.credentialId())
                .param(entry.username())
                .param(entry.status())
                .param(entry.statusListId())
                .param(entry.statusListIdx())
                .param(entry.issuedAt())
                .update();
    }

    public List<CredentialStatusEntry> findByStatusListId(String statusListId) {
        return jdbcClient.sql("SELECT credential_id, username, status, status_list_id, status_list_idx, issued_at FROM credential_status_entries WHERE status_list_id = ?")
                .param(statusListId)
                .query((rs, rowNum) -> new CredentialStatusEntry(
                        rs.getString("credential_id"),
                        rs.getString("username"),
                        rs.getString("status"),
                        rs.getString("status_list_id"),
                        rs.getInt("status_list_idx"),
                        rs.getTimestamp("issued_at").toInstant()
                ))
                .list();
    }

    public int updateStatus(String credentialId, String status) {
        return jdbcClient.sql("UPDATE credential_status_entries SET status = ? WHERE credential_id = ?")
                .param(status)
                .param(credentialId)
                .update();
    }
}
