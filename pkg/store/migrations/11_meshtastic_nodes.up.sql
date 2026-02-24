
CREATE TABLE meshtastic_nodes (
    node_id          BIGINT PRIMARY KEY,
    user_id          INT NULL,
    long_name        VARCHAR(39) NOT NULL DEFAULT '',
    short_name       VARCHAR(4) NOT NULL DEFAULT '',
    node_role        VARCHAR(20) NOT NULL DEFAULT '',
    hw_model         VARCHAR(30) NOT NULL DEFAULT '',
    primary_channel  VARCHAR(20) NOT NULL DEFAULT '',
    latitude         DOUBLE PRECISION NULL,
    longitude        DOUBLE PRECISION NULL,
    last_seen        TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_verified    TIMESTAMP WITH TIME ZONE NULL,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT valid_node_id CHECK (node_id >= 4 AND node_id < '4294967295'::BIGINT)
);

-- Migrate: pick the most-recently-seen row per node_id from the old table
INSERT INTO meshtastic_nodes (node_id, user_id, long_name, short_name, node_role, primary_channel, latitude, longitude, last_seen, last_verified)
SELECT DISTINCT ON (node_id)
    node_id, user_id, long_name, short_name, node_role,
    COALESCE(primary_channel, ''), latitude, longitude, last_seen, last_verified
FROM node_info
ORDER BY node_id, last_seen DESC NULLS LAST;

DROP TABLE node_info;
