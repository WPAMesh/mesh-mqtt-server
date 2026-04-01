CREATE TABLE blocked_nodes (
    node_id    BIGINT PRIMARY KEY,
    reason     TEXT NOT NULL DEFAULT '',
    blocked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    blocked_by INT NULL REFERENCES users(id) ON DELETE SET NULL
);
