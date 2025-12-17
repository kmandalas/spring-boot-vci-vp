CREATE TABLE IF NOT EXISTS wallet_unit_attestations (
    wua_id UUID PRIMARY KEY,
    wallet_public_key_thumbprint VARCHAR(255) NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    wscd_type VARCHAR(50) NOT NULL,
    wscd_security_level VARCHAR(50) NOT NULL,
    issued_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL
);
