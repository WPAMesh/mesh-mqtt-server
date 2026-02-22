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
	IsAdmin          bool      `db:"is_admin"`
	IsGatewayAllowed bool      `db:"gateway_allowed"`
	Created          time.Time `db:"created"`
}

// IsAdminOrAbove returns true if the user is an admin or a superuser.
func (u *User) IsAdminOrAbove() bool {
	return u.IsAdmin || u.IsSuperuser
}
