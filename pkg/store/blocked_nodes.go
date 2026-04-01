package store

import (
	"database/sql"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/jmoiron/sqlx"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
)

type BlockedNodeStore interface {
	IsBlocked(nodeID uint32) (bool, error)
	GetAll() ([]*models.BlockedNode, error)
	Block(nodeID uint32, reason string, blockedBy *int) error
	Unblock(nodeID uint32) error
}

type postgresBlockedNodeStore struct {
	db    *sqlx.DB
	cache *ttlcache.Cache[uint32, bool]
}

func NewBlockedNodeStore(dbconn *sqlx.DB) BlockedNodeStore {
	cache := ttlcache.New[uint32, bool](
		ttlcache.WithTTL[uint32, bool](15 * time.Minute),
	)
	go cache.Start()
	return &postgresBlockedNodeStore{
		db:    dbconn,
		cache: cache,
	}
}

func (s *postgresBlockedNodeStore) IsBlocked(nodeID uint32) (bool, error) {
	if item := s.cache.Get(nodeID, ttlcache.WithDisableTouchOnHit[uint32, bool]()); item != nil {
		return item.Value(), nil
	}
	var exists bool
	err := s.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM blocked_nodes WHERE node_id = $1)", nodeID)
	if err != nil {
		return false, err
	}
	s.cache.Set(nodeID, exists, 15*time.Minute)
	return exists, nil
}

func (s *postgresBlockedNodeStore) GetAll() ([]*models.BlockedNode, error) {
	var nodes []*models.BlockedNode
	err := s.db.Select(&nodes, "SELECT * FROM blocked_nodes ORDER BY blocked_at DESC")
	if err == sql.ErrNoRows {
		return []*models.BlockedNode{}, nil
	}
	return nodes, err
}

func (s *postgresBlockedNodeStore) Block(nodeID uint32, reason string, blockedBy *int) error {
	_, err := s.db.Exec(
		`INSERT INTO blocked_nodes (node_id, reason, blocked_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (node_id) DO UPDATE SET reason = $2, blocked_by = $3, blocked_at = NOW()`,
		nodeID, reason, blockedBy,
	)
	if err == nil {
		s.cache.Set(nodeID, true, 15*time.Minute)
	}
	return err
}

func (s *postgresBlockedNodeStore) Unblock(nodeID uint32) error {
	_, err := s.db.Exec("DELETE FROM blocked_nodes WHERE node_id = $1", nodeID)
	if err == nil {
		s.cache.Set(nodeID, false, 15*time.Minute)
	}
	return err
}
