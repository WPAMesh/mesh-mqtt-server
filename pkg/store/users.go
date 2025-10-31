package store

import (
	"database/sql"
	"log/slog"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/jmoiron/sqlx"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
)

var selectUsers = `SELECT u.* FROM users u`

type UserStore interface {
	GetByID(id int) (*models.User, error)
	GetByUserName(username string) (*models.User, error)
	GetByDiscordID(id int64) (*models.User, error)
	GetAll() ([]*models.User, error)
	SetDisplayName(user *models.User) error
	SetPassword(userID int, passwordHash, salt string) error
	UpdateUser(user *models.User) error
	AddUser(user *models.User) error
	DeleteUser(userID int) error
	IsSuperuser(id int) (bool, error)
	IsGatewayAllowed(id int) (bool, error)
}

type postgresUserStore struct {
	db *sqlx.DB
	//cfg    *conf.Config
	suCache      map[int]bool
	suCacheLock  sync.RWMutex
	gatewayCache *ttlcache.Cache[int, bool]
}

func NewUsers(dbconn *sqlx.DB) UserStore {
	cache := ttlcache.New[int, bool](
		ttlcache.WithTTL[int, bool](15 * time.Minute),
	)
	go cache.Start()
	return &postgresUserStore{
		db:           dbconn,
		suCache:      make(map[int]bool),
		gatewayCache: cache,
	}
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
	UPDATE users
	SET display_name = :display_name
	WHERE id = :id;
	`

	_, err := b.db.NamedExec(stmt, user)
	return err
}

func (b *postgresUserStore) SetPassword(userID int, passwordHash, salt string) error {
	stmt := `
	UPDATE users
	SET password_hash = $1, salt = $2
	WHERE id = $3;
	`

	_, err := b.db.Exec(stmt, passwordHash, salt, userID)
	return err
}

func (b *postgresUserStore) AddUser(user *models.User) error {
	stmt := `
	INSERT INTO users (display_name, discord_id, mqtt_user, password_hash, salt)
	VALUES (:display_name, :discord_id, :mqtt_user, :password_hash, :salt);
	`

	_, err := b.db.NamedExec(stmt, user)
	if err != nil {
		return err
	}
	// Not supported by postgres driver, call GetByUserName or GetByDiscordID instead
	//id, err := res.LastInsertId()
	//user.ID = int(id)
	return err
}

func (b *postgresUserStore) IsSuperuser(id int) (bool, error) {
	b.suCacheLock.RLock()
	if isSU, ok := b.suCache[id]; ok {
		b.suCacheLock.RUnlock()
		return isSU, nil
	}
	b.suCacheLock.RUnlock()
	slog.Debug("IsSuperuser cache miss, querying database", "user_id", id)
	u, err := b.GetByID(id)
	if u != nil {
		b.suCacheLock.Lock()
		b.suCache[id] = u.IsSuperuser
		b.suCacheLock.Unlock()
		return u.IsSuperuser, nil
	}
	return false, err
}

func (b *postgresUserStore) IsGatewayAllowed(id int) (bool, error) {
	if gwAllowed := b.gatewayCache.Get(id, ttlcache.WithDisableTouchOnHit[int, bool]()); gwAllowed != nil {
		return gwAllowed.Value(), nil
	}
	slog.Debug("IsGatewayAllowed cache miss, querying database", "user_id", id)
	u, err := b.GetByID(id)
	if u != nil {
		b.gatewayCache.Set(id, u.IsGatewayAllowed, 15*time.Minute)
		return u.IsGatewayAllowed, nil
	}
	return false, err
}

func (b *postgresUserStore) GetAll() ([]*models.User, error) {
	stmt := selectUsers + " ORDER BY u.mqtt_user;"
	var users []*models.User
	err := b.db.Select(&users, stmt)
	if err == sql.ErrNoRows {
		return []*models.User{}, nil
	}
	return users, err
}

func (b *postgresUserStore) UpdateUser(user *models.User) error {
	stmt := `
	UPDATE users
	SET display_name = :display_name,
	    mqtt_user = :mqtt_user,
	    is_superuser = :is_superuser,
	    gateway_allowed = :gateway_allowed
	WHERE id = :id;
	`

	_, err := b.db.NamedExec(stmt, user)
	if err == nil {
		// Invalidate caches for this user
		b.suCacheLock.Lock()
		delete(b.suCache, user.ID)
		b.suCacheLock.Unlock()
		b.gatewayCache.Delete(user.ID)
	}
	return err
}

func (b *postgresUserStore) DeleteUser(userID int) error {
	stmt := `DELETE FROM users WHERE id = $1;`

	_, err := b.db.Exec(stmt, userID)
	if err == nil {
		// Invalidate caches for this user
		b.suCacheLock.Lock()
		delete(b.suCache, userID)
		b.suCacheLock.Unlock()
		b.gatewayCache.Delete(userID)
	}
	return err
}
