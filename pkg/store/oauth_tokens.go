package store

import (
	"github.com/jmoiron/sqlx"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
)

var selectOAuthTokens = `
SELECT c.* FROM oauth_tokens c
`

type OAuthTokenStore interface {
	GetTokenForUser(userId int) (models.OAuthToken, error)
	GetTokenForDiscordID(discordId int64) (models.OAuthToken, error)
	SaveToken(cal models.OAuthToken) error
	RemoveToken(id int) error
}

type postgresOAuthTokenStore struct {
	db *sqlx.DB
	//cfg    *conf.Config
}

func NewOAuthTokens(dbconn *sqlx.DB) OAuthTokenStore {
	return &postgresOAuthTokenStore{db: dbconn}
}

func (b *postgresOAuthTokenStore) GetTokenForUser(userId int) (models.OAuthToken, error) {
	cal := models.OAuthToken{}
	err := b.db.Get(&cal, selectOAuthTokens+" WHERE user_id=$1", userId)
	return cal, err
}

func (b *postgresOAuthTokenStore) GetTokenForDiscordID(discordId int64) (models.OAuthToken, error) {
	cal := models.OAuthToken{}
	err := b.db.Get(&cal, selectOAuthTokens+" inner join users u ON c.user_id = u.id WHERE u.discord_id=$1", discordId)
	return cal, err
}

func (b *postgresOAuthTokenStore) SaveToken(cal models.OAuthToken) error {
	stmt := `
	INSERT INTO oauth_tokens (user_id, token_type, access_token, refresh_token, expiration)
	VALUES (:user_id, :token_type, :access_token, :refresh_token, :expiration)
	ON CONFLICT(user_id)
	DO UPDATE
	  SET token_type = :token_type, access_token = :access_token, refresh_token = :refresh_token, expiration = :expiration
	RETURNING user_id;
	`
	_, err := b.db.NamedExec(stmt, cal)
	return err
}

func (b *postgresOAuthTokenStore) RemoveToken(id int) error {
	stmt := `DELETE FROM oauth_tokens WHERE id = $1;`
	return b.db.QueryRow(stmt, id).Err()
}
