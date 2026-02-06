CREATE TABLE meshcore_nodes (
    pub_key    BYTEA PRIMARY KEY,
    node_type  SMALLINT NOT NULL DEFAULT 0,
    name       VARCHAR(64) NOT NULL DEFAULT '',
    latitude   DOUBLE PRECISION,
    longitude  DOUBLE PRECISION,
    last_seen  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
