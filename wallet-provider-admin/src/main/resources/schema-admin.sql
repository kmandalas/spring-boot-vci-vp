-- Admin Users (simplified - single user for Phase 1)
CREATE TABLE IF NOT EXISTS admin_users (
    id UUID PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    totp_secret VARCHAR(255),
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL
);

-- Seed default admin user (password: admin123)
INSERT INTO admin_users (id, username, password_hash, totp_secret, totp_enabled, created_at)
SELECT gen_random_uuid(), 'admin', '{bcrypt}$2a$10$t2x9nLFpE./1gudDkHd.vuc/F0rzhcoqp71gHXlLhIPEl6aNnnEzC', NULL, FALSE, CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT 1 FROM admin_users WHERE username = 'admin');

-- Audit Log (for WUA revocations)
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id UUID PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    target_id VARCHAR(255),
    details TEXT,
    created_at TIMESTAMPTZ NOT NULL
);

-- WUA Projections (local read model, populated from wallet-provider events)
CREATE TABLE IF NOT EXISTS wua_projections (
    wua_id UUID PRIMARY KEY,
    wallet_public_key_thumbprint VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    wscd_type VARCHAR(50) NOT NULL,
    wscd_security_level VARCHAR(50) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    status_list_id VARCHAR(36),
    status_list_idx INT,
    projected_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_wua_proj_thumbprint ON wua_projections (wallet_public_key_thumbprint);
CREATE INDEX IF NOT EXISTS idx_wua_proj_issued_at ON wua_projections (issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_wua_proj_status ON wua_projections (status);

-- Dashboard stats (single row, updated incrementally)
CREATE TABLE IF NOT EXISTS wua_stats (
    id INT PRIMARY KEY DEFAULT 1,
    total_count BIGINT NOT NULL DEFAULT 0,
    active_count BIGINT NOT NULL DEFAULT 0,
    revoked_count BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO wua_stats (id, total_count, active_count, revoked_count, updated_at)
SELECT 1, 0, 0, 0, CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT 1 FROM wua_stats WHERE id = 1);

-- Event cursor (tracks last consumed event ID from wallet-provider)
CREATE TABLE IF NOT EXISTS event_cursor (
    id INT PRIMARY KEY DEFAULT 1,
    last_event_id BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO event_cursor (id, last_event_id, updated_at)
SELECT 1, 0, CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT 1 FROM event_cursor WHERE id = 1);
