package com.example.walletprovider.repository;

import com.example.walletprovider.model.StatusList;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

@Repository
public class StatusListRepository {

    private final JdbcClient jdbcClient;

    public StatusListRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public void save(StatusList statusList) {
        jdbcClient.sql("""
            INSERT INTO status_lists (id, bits, max_entries, created_at)
            VALUES (:id, :bits, :maxEntries, :createdAt)
            """)
            .param("id", statusList.id())
            .param("bits", statusList.bits())
            .param("maxEntries", statusList.maxEntries())
            .param("createdAt", statusList.createdAt())
            .update();
    }

    public Optional<StatusList> findById(String id) {
        return jdbcClient.sql("SELECT * FROM status_lists WHERE id = :id")
            .param("id", id)
            .query(StatusList.class)
            .optional();
    }

    public List<StatusList> findAll() {
        return jdbcClient.sql("SELECT * FROM status_lists ORDER BY created_at DESC")
            .query(StatusList.class)
            .list();
    }

    /**
     * Get the first available status list (most recent).
     * In production, you'd have more sophisticated selection logic.
     */
    public Optional<StatusList> findFirstAvailable() {
        return jdbcClient.sql("SELECT * FROM status_lists ORDER BY created_at DESC LIMIT 1")
            .query(StatusList.class)
            .optional();
    }

    /**
     * Get all indices currently allocated in a status list.
     */
    public Set<Integer> getAllocatedIndices(String statusListId) {
        return Set.copyOf(
            jdbcClient.sql("SELECT status_list_idx FROM wallet_unit_attestations WHERE status_list_id = :listId")
                .param("listId", statusListId)
                .query(Integer.class)
                .list()
        );
    }

    /**
     * Count how many WUAs are in a specific status list.
     */
    public int countEntriesInList(String statusListId) {
        return jdbcClient.sql("SELECT COUNT(*) FROM wallet_unit_attestations WHERE status_list_id = :listId")
            .param("listId", statusListId)
            .query(Integer.class)
            .single();
    }
}
