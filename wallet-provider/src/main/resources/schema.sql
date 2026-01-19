-- Status Lists table (Token Status List per IETF draft-ietf-oauth-status-list)
CREATE TABLE IF NOT EXISTS status_lists (
    id VARCHAR(36) PRIMARY KEY,
    bits INT NOT NULL DEFAULT 1,
    max_entries INT NOT NULL DEFAULT 1000,
    created_at TIMESTAMP NOT NULL
);

-- Wallet Unit Attestations table
CREATE TABLE IF NOT EXISTS wallet_unit_attestations (
    wua_id UUID PRIMARY KEY,
    wallet_public_key_thumbprint VARCHAR(255) NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    wscd_type VARCHAR(50) NOT NULL,
    wscd_security_level VARCHAR(50) NOT NULL,
    issued_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    -- Token Status List fields
    status_list_id VARCHAR(36),
    status_list_idx INT,
    FOREIGN KEY (status_list_id) REFERENCES status_lists(id)
);

-- Create default status list on startup
INSERT INTO status_lists (id, bits, max_entries, created_at)
SELECT '1', 1, 1000, CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT 1 FROM status_lists WHERE id = '1');
