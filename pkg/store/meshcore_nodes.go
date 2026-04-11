package store

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
)

var selectMeshCoreNodes = `SELECT * FROM meshcore_nodes`

// MeshCoreNodeStore provides database operations for MeshCore nodes.
type MeshCoreNodeStore interface {
	GetNode(pubKey []byte) (*models.MeshCoreNodeInfo, error)
	SaveNode(node *models.MeshCoreNodeInfo) error
	GetAllNodes() ([]*models.MeshCoreNodeInfo, error)
	GetNodesByPubKeys(pubKeys []string) ([]*models.MeshCoreNodeInfo, error)
}

type postgresMeshCoreNodeStore struct {
	db *sqlx.DB
}

// NewMeshCoreNodeDB creates a new MeshCore node store.
func NewMeshCoreNodeDB(dbconn *sqlx.DB) MeshCoreNodeStore {
	return &postgresMeshCoreNodeStore{db: dbconn}
}

// GetNode retrieves a MeshCore node by its public key.
func (s *postgresMeshCoreNodeStore) GetNode(pubKey []byte) (*models.MeshCoreNodeInfo, error) {
	query := selectMeshCoreNodes + " WHERE pub_key = $1;"
	var node models.MeshCoreNodeInfo
	err := s.db.Get(&node, query, pubKey)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &node, nil
}

// SaveNode inserts or updates a MeshCore node in the database.
func (s *postgresMeshCoreNodeStore) SaveNode(node *models.MeshCoreNodeInfo) error {
	stmt := `
	INSERT INTO meshcore_nodes (pub_key, node_type, name, latitude, longitude, is_direct, user_id, last_seen)
	VALUES (:pub_key, :node_type, :name, :latitude, :longitude, :is_direct, :user_id, :last_seen)
	ON CONFLICT (pub_key)
	DO UPDATE SET
		node_type = :node_type,
		name = :name,
		latitude = :latitude,
		longitude = :longitude,
		is_direct = :is_direct,
		user_id = :user_id,
		last_seen = :last_seen
	;`

	_, err := s.db.NamedExec(stmt, node)
	return err
}

// GetAllNodes retrieves all MeshCore nodes from the database.
func (s *postgresMeshCoreNodeStore) GetAllNodes() ([]*models.MeshCoreNodeInfo, error) {
	query := selectMeshCoreNodes + ";"
	nodes := []*models.MeshCoreNodeInfo{}
	err := s.db.Select(&nodes, query)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return nodes, nil
}

// GetNodesByPubKeys retrieves MeshCore nodes by their public keys.
func (s *postgresMeshCoreNodeStore) GetNodesByPubKeys(pubKeys []string) ([]*models.MeshCoreNodeInfo, error) {
	if len(pubKeys) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(pubKeys))
	args := make([]any, len(pubKeys))
	for i, pk := range pubKeys {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = pk
	}
	query := selectMeshCoreNodes + " WHERE encode(pub_key, 'hex') IN (" + strings.Join(placeholders, ", ") + ")"
	nodes := []*models.MeshCoreNodeInfo{}
	err := s.db.Select(&nodes, query, args...)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return nodes, nil
}
