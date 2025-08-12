package models

import "time"

type MqttUser struct {
	ID           int       `db:"id"`
	DiscordID    *int64    `db:"discord_id"`
	UserName     string    `db:"username"`
	PasswordHash string    `db:"password_hash"`
	Salt         string    `db:"salt"`
	Created      time.Time `db:"created"`
}
