ALTER TABLE meshcore_nodes ADD COLUMN user_id INT REFERENCES users(id);
