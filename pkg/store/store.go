package store

import (
	"database/sql"
	"embed"
	"log"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jmoiron/sqlx"
)

//go:embed migrations/*.sql
var dbMigrations embed.FS

// Stores one stop for stores
type Stores struct {
	Users          UserStore
	OAuthTokens    OAuthTokenStore
	NodeDB         NodeInfoStore
	MeshCoreNodes  MeshCoreNodeStore
	db             *sqlx.DB
}

// New create all the stores
func New(dbconn *sqlx.DB) (*Stores, error) {
	return &Stores{
		db:            dbconn,
		Users:         NewUsers(dbconn),
		OAuthTokens:   NewOAuthTokens(dbconn),
		NodeDB:        NewNodeDB(dbconn),
		MeshCoreNodes: NewMeshCoreNodeDB(dbconn),
	}, nil
}

func (b *Stores) RunMigrations() error {
	// get base path
	driver, err := postgres.WithInstance(b.db.DB, &postgres.Config{})

	if err != nil {
		return err
	}

	d, err := iofs.New(dbMigrations, "migrations")
	if err != nil {
		return err
	}

	m, err := migrate.NewWithInstance("iofs", d, "postgres", driver)

	if err != nil {
		return err
	}

	err = m.Up()

	switch err {
	case migrate.ErrNoChange:
		return nil
	}

	return err
}

func queryAndMap[T any, PT interface{ *T }](db *sqlx.DB, query string, args ...any) (PT, error) {

	var t T
	err := db.QueryRowx(query, args...).Scan(&t)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		log.Printf("Error fetching record: %v", err.Error())
		return nil, err
	}

	return &t, nil
}
