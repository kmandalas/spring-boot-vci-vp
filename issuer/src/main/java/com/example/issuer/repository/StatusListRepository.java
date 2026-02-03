package com.example.issuer.repository;

import com.example.issuer.model.StatusList;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Repository
public class StatusListRepository {

    private final JdbcClient jdbcClient;

    public StatusListRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public void save(StatusList statusList) {
        jdbcClient.sql("INSERT INTO status_lists (id, bits, max_entries, created_at) VALUES (?, ?, ?, ?)")
                .param(statusList.id())
                .param(statusList.bits())
                .param(statusList.maxEntries())
                .param(statusList.createdAt())
                .update();
    }

    public Optional<StatusList> findById(String id) {
        return jdbcClient.sql("SELECT id, bits, max_entries, created_at FROM status_lists WHERE id = ?")
                .param(id)
                .query((rs, rowNum) -> new StatusList(
                        rs.getString("id"),
                        rs.getInt("bits"),
                        rs.getInt("max_entries"),
                        rs.getTimestamp("created_at").toInstant()
                ))
                .optional();
    }

    public Set<Integer> getAllocatedIndices(String statusListId) {
        return jdbcClient.sql("SELECT status_list_idx FROM credential_status_entries WHERE status_list_id = ?")
                .param(statusListId)
                .query((rs, rowNum) -> rs.getInt("status_list_idx"))
                .list()
                .stream()
                .collect(Collectors.toSet());
    }

    public int countEntriesInList(String statusListId) {
        return jdbcClient.sql("SELECT COUNT(*) FROM credential_status_entries WHERE status_list_id = ?")
                .param(statusListId)
                .query((rs, rowNum) -> rs.getInt(1))
                .single();
    }
}
