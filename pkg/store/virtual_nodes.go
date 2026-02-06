package store

import (
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
)

var selectVirtualNodes = `SELECT * FROM virtual_nodes`

// VirtualNodeStore provides database operations for virtual (bridged) nodes.
type VirtualNodeStore interface {
	// GetByNodeID retrieves a virtual node by its Meshtastic node ID.
	GetByNodeID(nodeID uint32) (*models.VirtualNode, error)
	// GetByExternalID retrieves a virtual node by source and external ID.
	GetByExternalID(source, externalID string) (*models.VirtualNode, error)
	// IsVirtualNode checks if a node ID belongs to a virtual node.
	IsVirtualNode(nodeID uint32) (bool, error)
	// Save inserts or updates a virtual node.
	Save(node *models.VirtualNode) error
	// UpdateLastSeen updates the last_seen timestamp for a virtual node.
	UpdateLastSeen(nodeID uint32) error
	// GetAll retrieves all virtual nodes.
	GetAll() ([]*models.VirtualNode, error)
	// GetBySource retrieves all virtual nodes from a specific source.
	GetBySource(source string) ([]*models.VirtualNode, error)
}

type postgresVirtualNodeStore struct {
	db *sqlx.DB
}

// NewVirtualNodeStore creates a new virtual node store.
func NewVirtualNodeStore(dbconn *sqlx.DB) VirtualNodeStore {
	return &postgresVirtualNodeStore{db: dbconn}
}

// GetByNodeID retrieves a virtual node by its Meshtastic node ID.
func (s *postgresVirtualNodeStore) GetByNodeID(nodeID uint32) (*models.VirtualNode, error) {
	query := selectVirtualNodes + " WHERE node_id = $1;"
	var node models.VirtualNode
	err := s.db.Get(&node, query, nodeID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &node, nil
}

// GetByExternalID retrieves a virtual node by source and external ID.
func (s *postgresVirtualNodeStore) GetByExternalID(source, externalID string) (*models.VirtualNode, error) {
	query := selectVirtualNodes + " WHERE source = $1 AND external_id = $2;"
	var node models.VirtualNode
	err := s.db.Get(&node, query, source, externalID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &node, nil
}

// IsVirtualNode checks if a node ID belongs to a virtual node.
func (s *postgresVirtualNodeStore) IsVirtualNode(nodeID uint32) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM virtual_nodes WHERE node_id = $1);`
	var exists bool
	err := s.db.Get(&exists, query, nodeID)
	return exists, err
}

// Save inserts or updates a virtual node.
func (s *postgresVirtualNodeStore) Save(node *models.VirtualNode) error {
	stmt := `
	INSERT INTO virtual_nodes (node_id, source, external_id, display_name, first_seen, last_seen)
	VALUES (:node_id, :source, :external_id, :display_name, :first_seen, :last_seen)
	ON CONFLICT (node_id)
	DO UPDATE SET
		display_name = :display_name,
		last_seen = :last_seen
	;`

	_, err := s.db.NamedExec(stmt, node)
	return err
}

// UpdateLastSeen updates the last_seen timestamp for a virtual node.
func (s *postgresVirtualNodeStore) UpdateLastSeen(nodeID uint32) error {
	query := `UPDATE virtual_nodes SET last_seen = $1 WHERE node_id = $2;`
	_, err := s.db.Exec(query, time.Now(), nodeID)
	return err
}

// GetAll retrieves all virtual nodes.
func (s *postgresVirtualNodeStore) GetAll() ([]*models.VirtualNode, error) {
	query := selectVirtualNodes + ";"
	nodes := []*models.VirtualNode{}
	err := s.db.Select(&nodes, query)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return nodes, nil
}

// GetBySource retrieves all virtual nodes from a specific source.
func (s *postgresVirtualNodeStore) GetBySource(source string) ([]*models.VirtualNode, error) {
	query := selectVirtualNodes + " WHERE source = $1;"
	nodes := []*models.VirtualNode{}
	err := s.db.Select(&nodes, query, source)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return nodes, nil
}
