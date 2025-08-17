package models

import "time"

type User struct {
	ID           int       `db:"id"`
	DisplayName  *string   `db:"display_name"`
	DiscordID    *int64    `db:"discord_id"`
	UserName     string    `db:"mqtt_user"`
	PasswordHash string    `db:"password_hash"`
	Salt         string    `db:"salt"`
	Created      time.Time `db:"created"`
}

type DiscordUser struct {
	ID            string  `json:"id"`
	Username      string  `json:"username"`
	Descriminator string  `json:"discriminator"`
	GlobalName    *string `json:"global_name"`
	Avatar        *string `json:"avatar"`
}

type DiscordGuildMember struct {
	User    *DiscordUser `json:"user"`
	Nick    *string      `json:"nick"`
	Roles   []string     `json:"roles"`
	Pending *bool        `json:"pending"`
	Flags   int          `json:"flags"`
}
