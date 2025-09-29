package models

import "time"

type User struct {
	ID               int       `db:"id"`
	DisplayName      *string   `db:"display_name"`
	DiscordID        *int64    `db:"discord_id"`
	UserName         string    `db:"mqtt_user"`
	PasswordHash     string    `db:"password_hash"`
	Salt             string    `db:"salt"`
	IsSuperuser      bool      `db:"is_superuser"`
	IsGatewayAllowed bool      `db:"gateway_allowed"`
	Created          time.Time `db:"created"`
}
