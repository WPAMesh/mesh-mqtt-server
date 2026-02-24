
CREATE TABLE node_info (
    node_id          BIGINT NOT NULL,
    user_id          INT NOT NULL,
    long_name        VARCHAR(39) NOT NULL DEFAULT '',
    short_name       VARCHAR(4) NOT NULL DEFAULT '',
    node_role        VARCHAR(20) NOT NULL DEFAULT '',
    primary_channel  VARCHAR(20) NOT NULL DEFAULT '',
    latitude         DOUBLE PRECISION NULL,
    longitude        DOUBLE PRECISION NULL,
    last_seen        TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_verified    TIMESTAMP WITH TIME ZONE NULL,

    PRIMARY KEY (user_id, node_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT valid_node_id CHECK (node_id >= 4 AND node_id < '4294967295'::BIGINT)
);

-- Best-effort migration back: only nodes with a user_id can be restored
INSERT INTO node_info (node_id, user_id, long_name, short_name, node_role, primary_channel, latitude, longitude, last_seen, last_verified)
SELECT node_id, user_id, long_name, short_name, node_role, primary_channel, latitude, longitude, last_seen, last_verified
FROM meshtastic_nodes
WHERE user_id IS NOT NULL;

DROP TABLE meshtastic_nodes;
