package store

import (
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
	meshtastic "github.com/kabili207/meshtastic-go/core"

	"github.com/kabili207/mesh-mqtt-server/pkg/models"
)

var selectNodes = `SELECT n.* FROM meshtastic_nodes n`

type NodeInfoStore interface {
	GetNode(nodeId uint32) (*models.NodeInfo, error)
	GetAllNodes() ([]*models.NodeInfo, error)
	GetByUserID(userId int) ([]*models.NodeInfo, error)
	GetByUserIDExceptNodeIDs(userId int, nodeIDs []uint32) ([]*models.NodeInfo, error)
	GetAllExceptNodeIDs(nodeIDs []uint32) ([]*models.NodeInfo, error)
	SaveInfo(node *models.NodeInfo) error
	SaveNodeIdentity(nodeId uint32, longName, shortName, role, hwModel string) error
}

type postgresNodeInfoStore struct {
	db *sqlx.DB
}

func NewNodeDB(dbconn *sqlx.DB) NodeInfoStore {
	return &postgresNodeInfoStore{db: dbconn}
}

func (b *postgresNodeInfoStore) GetNode(nodeId uint32) (*models.NodeInfo, error) {
	stmt := selectNodes + " WHERE n.node_id=$1;"
	var obj models.NodeInfo
	err := b.db.Get(&obj, stmt, nodeId)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &obj, err
}

func (b *postgresNodeInfoStore) GetByUserID(userId int) ([]*models.NodeInfo, error) {
	stmt := selectNodes + " WHERE n.user_id = $1;"
	obj := []*models.NodeInfo{}
	err := b.db.Select(&obj, stmt, userId)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return obj, err
}

func (b *postgresNodeInfoStore) GetAllNodes() ([]*models.NodeInfo, error) {
	stmt := selectNodes + ";"
	obj := []*models.NodeInfo{}
	err := b.db.Select(&obj, stmt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return obj, err
}

func (b *postgresNodeInfoStore) GetByUserIDExceptNodeIDs(userId int, nodeIDs []uint32) ([]*models.NodeInfo, error) {
	if len(nodeIDs) == 0 {
		return b.GetByUserID(userId)
	}
	stmt := selectNodes + " WHERE n.user_id = ? AND n.node_id NOT IN(?);"
	obj := []*models.NodeInfo{}
	query, args, err := sqlx.In(stmt, userId, nodeIDs)
	query = b.db.Rebind(query)
	err = b.db.Select(&obj, query, args...)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return obj, err
}

func (b *postgresNodeInfoStore) GetAllExceptNodeIDs(nodeIDs []uint32) ([]*models.NodeInfo, error) {
	if len(nodeIDs) == 0 {
		stmt := selectNodes + " WHERE n.user_id IS NOT NULL;"
		obj := []*models.NodeInfo{}
		err := b.db.Select(&obj, stmt)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return obj, err
	}
	stmt := selectNodes + " WHERE n.user_id IS NOT NULL AND n.node_id NOT IN(?);"
	obj := []*models.NodeInfo{}
	query, args, err := sqlx.In(stmt, nodeIDs)
	query = b.db.Rebind(query)
	err = b.db.Select(&obj, query, args...)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return obj, err
}

func (b *postgresNodeInfoStore) SaveInfo(nodeInfo *models.NodeInfo) error {
	stmt := `
	INSERT INTO meshtastic_nodes (node_id, user_id, long_name, short_name, node_role, hw_model, primary_channel, latitude, longitude, last_seen, last_verified)
	VALUES (:node_id, :user_id, :long_name, :short_name, :node_role, :hw_model, :primary_channel, :latitude, :longitude, :last_seen, :last_verified)
	ON CONFLICT(node_id)
	DO UPDATE SET
	    user_id = EXCLUDED.user_id,
	    long_name = EXCLUDED.long_name,
	    short_name = EXCLUDED.short_name,
	    node_role = EXCLUDED.node_role,
	    hw_model = EXCLUDED.hw_model,
	    primary_channel = EXCLUDED.primary_channel,
	    latitude = CASE WHEN meshtastic_nodes.user_id IS DISTINCT FROM EXCLUDED.user_id
	                    THEN CAST(NULL AS DOUBLE PRECISION) ELSE COALESCE(EXCLUDED.latitude, meshtastic_nodes.latitude) END,
	    longitude = CASE WHEN meshtastic_nodes.user_id IS DISTINCT FROM EXCLUDED.user_id
	                     THEN CAST(NULL AS DOUBLE PRECISION) ELSE COALESCE(EXCLUDED.longitude, meshtastic_nodes.longitude) END,
	    last_seen = EXCLUDED.last_seen,
	    last_verified = CASE WHEN meshtastic_nodes.user_id IS DISTINCT FROM EXCLUDED.user_id
	                         THEN CAST(NULL AS TIMESTAMPTZ) ELSE EXCLUDED.last_verified END
	;
	`

	_, err := b.db.NamedExec(stmt, nodeInfo)
	return err
}

func (b *postgresNodeInfoStore) SaveNodeIdentity(nodeId uint32, longName, shortName, role, hwModel string) error {
	now := time.Now()
	stmt := `
	INSERT INTO meshtastic_nodes (node_id, long_name, short_name, node_role, hw_model, last_seen)
	VALUES ($1, $2, $3, $4, $5, $6)
	ON CONFLICT(node_id)
	DO UPDATE SET
	    long_name = $2,
	    short_name = $3,
	    node_role = $4,
	    hw_model = $5,
	    last_seen = $6
	;
	`

	nid := meshtastic.NodeID(nodeId)
	if longName == "" {
		longName = nid.DefaultLongName()
	}
	if shortName == "" {
		shortName = nid.DefaultShortName()
	}

	_, err := b.db.Exec(stmt, nodeId, longName, shortName, role, hwModel, now)
	return err
}
