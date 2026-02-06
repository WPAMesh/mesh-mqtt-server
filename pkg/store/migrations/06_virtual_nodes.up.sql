CREATE TABLE virtual_nodes (
    node_id      BIGINT PRIMARY KEY,
    source       VARCHAR(32) NOT NULL,
    external_id  VARCHAR(128) NOT NULL,
    display_name VARCHAR(64) NOT NULL DEFAULT '',
    first_seen   TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen    TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_virtual_nodes_source ON virtual_nodes(source);
CREATE UNIQUE INDEX idx_virtual_nodes_external ON virtual_nodes(source, external_id);
