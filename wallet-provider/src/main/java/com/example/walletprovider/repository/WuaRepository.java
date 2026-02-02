package com.example.walletprovider.repository;

import com.example.walletprovider.model.WalletUnitAttestation;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public class WuaRepository {

    private final JdbcClient jdbcClient;

    public WuaRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public void save(WalletUnitAttestation wua) {
        jdbcClient.sql("""
            INSERT INTO wallet_unit_attestations
            (wua_id, wallet_public_key_thumbprint, status, wscd_type, wscd_security_level, issued_at, expires_at, status_list_id, status_list_idx)
            VALUES (:wuaId, :walletPublicKeyThumbprint, :status, :wscdType, :wscdSecurityLevel, :issuedAt, :expiresAt, :statusListId, :statusListIdx)
            """)
            .param("wuaId", wua.wuaId())
            .param("walletPublicKeyThumbprint", wua.walletPublicKeyThumbprint())
            .param("status", wua.status())
            .param("wscdType", wua.wscdType())
            .param("wscdSecurityLevel", wua.wscdSecurityLevel())
            .param("issuedAt", wua.issuedAt())
            .param("expiresAt", wua.expiresAt())
            .param("statusListId", wua.statusListId())
            .param("statusListIdx", wua.statusListIdx())
            .update();
    }

    public Optional<WalletUnitAttestation> findById(UUID wuaId) {
        return jdbcClient.sql("SELECT * FROM wallet_unit_attestations WHERE wua_id = :wuaId")
            .param("wuaId", wuaId)
            .query(WalletUnitAttestation.class)
            .optional();
    }

    public Optional<WalletUnitAttestation> findByWalletPublicKeyThumbprint(String thumbprint) {
        return jdbcClient.sql("SELECT * FROM wallet_unit_attestations WHERE wallet_public_key_thumbprint = :thumbprint")
            .param("thumbprint", thumbprint)
            .query(WalletUnitAttestation.class)
            .optional();
    }

    public boolean existsByWalletPublicKeyThumbprint(String thumbprint) {
        return jdbcClient.sql("SELECT 1 FROM wallet_unit_attestations WHERE wallet_public_key_thumbprint = :thumbprint LIMIT 1")
            .param("thumbprint", thumbprint)
            .query(Integer.class)
            .optional()
            .isPresent();
    }

    /**
     * Find all WUAs in a specific status list (for generating status list token).
     */
    public java.util.List<WalletUnitAttestation> findByStatusListId(String statusListId) {
        return jdbcClient.sql("SELECT * FROM wallet_unit_attestations WHERE status_list_id = :statusListId")
            .param("statusListId", statusListId)
            .query(WalletUnitAttestation.class)
            .list();
    }

}
