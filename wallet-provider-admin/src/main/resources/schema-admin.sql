-- Admin Users (simplified - single user for Phase 1)
CREATE TABLE IF NOT EXISTS admin_users (
    id UUID PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    totp_secret VARCHAR(255),
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL
);

-- Audit Log (for WUA revocations)
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id UUID PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    target_id VARCHAR(255),
    details TEXT,
    created_at TIMESTAMP NOT NULL
);

-- Admin user is created by AdminUserInitializer on startup
