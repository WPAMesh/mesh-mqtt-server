package store

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
)

var selectUsers = `SELECT u.* FROM users u`

type UserStore interface {
	GetByID(id int) (*models.User, error)
	GetByUserName(username string) (*models.User, error)
	GetByDiscordID(id int64) (*models.User, error)
	SetDisplayName(user *models.User) error
}

type postgresUserStore struct {
	db *sqlx.DB
	//cfg    *conf.Config
}

func NewUsers(dbconn *sqlx.DB) UserStore {
	return &postgresUserStore{db: dbconn}
}

func (b *postgresUserStore) GetByID(id int) (*models.User, error) {
	getTokenStatement := selectUsers + " WHERE u.id=$1;"
	var user models.User
	err := b.db.Get(&user, getTokenStatement, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &user, err
}

func (b *postgresUserStore) GetByUserName(username string) (*models.User, error) {
	getTokenStatement := selectUsers + " WHERE u.mqtt_user = $1;"
	var user models.User
	err := b.db.Get(&user, getTokenStatement, username)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &user, err
}

func (b *postgresUserStore) GetByDiscordID(id int64) (*models.User, error) {
	getTokenStatement := selectUsers + " WHERE u.discord_id = $1;"
	var user models.User
	err := b.db.Get(&user, getTokenStatement, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &user, err
}

func (b *postgresUserStore) SetDisplayName(user *models.User) error {
	stmt := `
	UPDATE mqtt_user
	SET display_name = :display_name
	WHERE id = :id;
	`

	_, err := b.db.NamedExec(stmt, user)
	return err
}
