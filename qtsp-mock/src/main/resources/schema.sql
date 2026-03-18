CREATE TABLE IF NOT EXISTS qtsp_credentials (
    credential_id  VARCHAR(36) PRIMARY KEY,
    user_id        VARCHAR(255) NOT NULL,
    private_key    BYTEA NOT NULL,
    public_key     BYTEA NOT NULL,
    certificate    BYTEA NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_qtsp_credentials_user_id ON qtsp_credentials (user_id);
