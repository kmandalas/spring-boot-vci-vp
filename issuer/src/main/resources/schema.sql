CREATE TABLE IF NOT EXISTS status_lists (
    id VARCHAR(36) PRIMARY KEY,
    bits INT NOT NULL DEFAULT 1,
    max_entries INT NOT NULL DEFAULT 1000,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS credential_status_entries (
    credential_id VARCHAR(255) PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    status_list_id VARCHAR(36) NOT NULL,
    status_list_idx INT NOT NULL,
    issued_at TIMESTAMP NOT NULL,
    FOREIGN KEY (status_list_id) REFERENCES status_lists(id)
);
