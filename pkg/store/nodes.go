package store

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
)

var selectNodes = `SELECT n.* FROM node_info n`

type NodeInfoStore interface {
	GetNode(nodeId uint32, userId int) (*models.NodeInfo, error)
	GetAllNodes() ([]*models.NodeInfo, error)
	GetByUserID(userId int) ([]*models.NodeInfo, error)
	GetByUserIDExceptNodeIDs(userId int, nodeIDs []uint32) ([]*models.NodeInfo, error)
	GetAllExceptNodeIDs(nodeIDs []uint32) ([]*models.NodeInfo, error)
	GetByDiscordID(id int64) (*models.NodeInfo, error)
	SaveInfo(user *models.NodeInfo) error
}

type postgresNodeInfoStore struct {
	db *sqlx.DB
	//cfg    *conf.Config
}

func NewNodeDB(dbconn *sqlx.DB) NodeInfoStore {
	return &postgresNodeInfoStore{db: dbconn}
}

func (b *postgresNodeInfoStore) GetNode(nodeId uint32, userId int) (*models.NodeInfo, error) {
	getTokenStatement := selectNodes + " WHERE n.node_id=$1 AND n.user_id=$2;"
	var obj models.NodeInfo
	err := b.db.Get(&obj, getTokenStatement, nodeId, userId)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &obj, err
}

func (b *postgresNodeInfoStore) GetByUserID(userId int) ([]*models.NodeInfo, error) {
	getTokenStatement := selectNodes + " WHERE n.user_id = $1;"
	obj := []*models.NodeInfo{}
	err := b.db.Select(&obj, getTokenStatement, userId)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return obj, err
}

func (b *postgresNodeInfoStore) GetAllNodes() ([]*models.NodeInfo, error) {
	getTokenStatement := selectNodes + " ;"
	obj := []*models.NodeInfo{}
	err := b.db.Select(&obj, getTokenStatement)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return obj, err
}

func (b *postgresNodeInfoStore) GetByUserIDExceptNodeIDs(userId int, nodeIDs []uint32) ([]*models.NodeInfo, error) {
	if len(nodeIDs) == 0 {
		return b.GetByUserID(userId)
	}
	getTokenStatement := selectNodes + " WHERE n.user_id = ? AND n.node_id NOT IN(?);"
	obj := []*models.NodeInfo{}
	query, args, err := sqlx.In(getTokenStatement, userId, nodeIDs)
	query = b.db.Rebind(query)
	err = b.db.Select(&obj, query, args...)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return obj, err
}

func (b *postgresNodeInfoStore) GetAllExceptNodeIDs(nodeIDs []uint32) ([]*models.NodeInfo, error) {
	if len(nodeIDs) == 0 {
		return b.GetAllNodes()
	}
	getTokenStatement := selectNodes + " WHERE n.node_id NOT IN(?);"
	obj := []*models.NodeInfo{}
	query, args, err := sqlx.In(getTokenStatement, nodeIDs)
	query = b.db.Rebind(query)
	err = b.db.Select(&obj, query, args...)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return obj, err
}

func (b *postgresNodeInfoStore) GetByDiscordID(id int64) (*models.NodeInfo, error) {
	getTokenStatement := selectNodes + " INNER JOIN users u ON u.id = n.user_id WHERE u.discord_id = $1;"
	var obj models.NodeInfo
	err := b.db.Get(&obj, getTokenStatement, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &obj, err
}

func (b *postgresNodeInfoStore) SaveInfo(nodeInfo *models.NodeInfo) error {
	stmt := `
	INSERT INTO node_info (node_id, user_id, long_name, short_name, node_role, primary_channel, last_seen, last_verified)
	VALUES (:node_id, :user_id, :long_name, :short_name, :node_role, :primary_channel, :last_seen, :last_verified)
	ON CONFLICT(node_id, user_id)
	DO UPDATE
	  SET long_name = :long_name,
		  short_name = :short_name,
		  node_role = :node_role,
		  primary_channel = :primary_channel,
		  last_seen = :last_seen,
		  last_verified = :last_verified
	;
	`

	_, err := b.db.NamedExec(stmt, nodeInfo)
	return err
}
