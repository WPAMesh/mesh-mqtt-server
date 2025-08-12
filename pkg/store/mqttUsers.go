package store

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
)

var selectUsers = `SELECT u.* FROM mqtt_user u`

type UserStore interface {
	GetByID(id int) (*models.MqttUser, error)
	GetByUserName(username string) (*models.MqttUser, error)
	GetByDiscordID(id int64) (*models.MqttUser, error)
	SetDiscordID(user *models.MqttUser) error
}

type postgresUserStore struct {
	db *sqlx.DB
	//cfg    *conf.Config
}

func NewUsers(dbconn *sqlx.DB) UserStore {
	return &postgresUserStore{db: dbconn}
}

func (b *postgresUserStore) GetByID(id int) (*models.MqttUser, error) {
	getTokenStatement := selectUsers + " WHERE u.id=$1;"
	var user models.MqttUser
	err := b.db.Get(&user, getTokenStatement, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &user, err
}

func (b *postgresUserStore) GetByUserName(username string) (*models.MqttUser, error) {
	getTokenStatement := selectUsers + " WHERE u.username = $1;"
	var user models.MqttUser
	err := b.db.Get(&user, getTokenStatement, username)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &user, err
}

func (b *postgresUserStore) GetByDiscordID(id int64) (*models.MqttUser, error) {
	getTokenStatement := selectUsers + " WHERE u.discord_id = $1;"
	var user models.MqttUser
	err := b.db.Get(&user, getTokenStatement, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &user, err
}

func (b *postgresUserStore) SetDiscordID(user *models.MqttUser) error {
	stmt := `
	UPDATE mqtt_user
	SET discord_id = :discord_id
	WHERE id = :id;
	`

	_, err := b.db.NamedExec(stmt, user)
	return err
}
