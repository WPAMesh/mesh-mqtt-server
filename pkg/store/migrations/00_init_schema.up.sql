
CREATE TABLE mqtt_user (
    id serial PRIMARY KEY,
    username text NOT NULL UNIQUE,
    discord_id bigint NULL,
    password_hash  text NOT NULL,
    salt text NOT NULL,
    created timestamp with time zone DEFAULT NOW(),
    
    constraint idx_discord_id UNIQUE (discord_id)
);