CREATE TABLE users (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    display_name text NULL,
    discord_id bigint NULL,
    mqtt_user text NOT NULL UNIQUE,
    password_hash  text NOT NULL,
    salt text NOT NULL,
    created timestamp with time zone DEFAULT NOW(),
    
    constraint idx_user_mqtt_username UNIQUE (mqtt_user),
    constraint idx_user_discord_id UNIQUE (discord_id)
);


CREATE TABLE oauth_tokens (
	user_id INT NOT NULL PRIMARY KEY,
	token_type VARCHAR(20),
	access_token VARCHAR(2048),
	refresh_token VARCHAR(512),
	expiration TIMESTAMP(2) WITH TIME ZONE,
    constraint idx_oauth_user_id UNIQUE (user_id)
	FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE ON UPDATE CASCADE
);