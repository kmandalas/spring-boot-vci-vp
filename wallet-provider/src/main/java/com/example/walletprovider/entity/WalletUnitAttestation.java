package com.example.walletprovider.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "wallet_unit_attestations")
public class WalletUnitAttestation {

    @Id
    @Column(name = "wua_id")
    private UUID wuaId;

    @Column(name = "wallet_public_key_thumbprint", nullable = false, unique = true)
    private String walletPublicKeyThumbprint;

    @Column(name = "status", nullable = false)
    @Enumerated(EnumType.STRING)
    private WuaStatus status;

    @Column(name = "wscd_type", nullable = false)
    private String wscdType;

    @Column(name = "wscd_security_level", nullable = false)
    private String wscdSecurityLevel;

    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    public enum WuaStatus {
        ACTIVE, REVOKED
    }

    public WalletUnitAttestation() {
    }

    public WalletUnitAttestation(UUID wuaId, String walletPublicKeyThumbprint, String wscdType,
                                  String wscdSecurityLevel, Instant issuedAt, Instant expiresAt) {
        this.wuaId = wuaId;
        this.walletPublicKeyThumbprint = walletPublicKeyThumbprint;
        this.status = WuaStatus.ACTIVE;
        this.wscdType = wscdType;
        this.wscdSecurityLevel = wscdSecurityLevel;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    public UUID getWuaId() {
        return wuaId;
    }

    public void setWuaId(UUID wuaId) {
        this.wuaId = wuaId;
    }

    public String getWalletPublicKeyThumbprint() {
        return walletPublicKeyThumbprint;
    }

    public void setWalletPublicKeyThumbprint(String walletPublicKeyThumbprint) {
        this.walletPublicKeyThumbprint = walletPublicKeyThumbprint;
    }

    public WuaStatus getStatus() {
        return status;
    }

    public void setStatus(WuaStatus status) {
        this.status = status;
    }

    public String getWscdType() {
        return wscdType;
    }

    public void setWscdType(String wscdType) {
        this.wscdType = wscdType;
    }

    public String getWscdSecurityLevel() {
        return wscdSecurityLevel;
    }

    public void setWscdSecurityLevel(String wscdSecurityLevel) {
        this.wscdSecurityLevel = wscdSecurityLevel;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Instant issuedAt) {
        this.issuedAt = issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }
}
