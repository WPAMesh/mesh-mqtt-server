package models

import (
	"time"

	"github.com/kabili207/mesh-mqtt-server/pkg/meshcore"
)

// MeshCoreNodeInfo represents a MeshCore node stored in the database.
type MeshCoreNodeInfo struct {
	PubKey    []byte     `db:"pub_key"`
	NodeType  int16      `db:"node_type"`
	Name      string     `db:"name"`
	Latitude  *float64   `db:"latitude"`
	Longitude *float64   `db:"longitude"`
	LastSeen  *time.Time `db:"last_seen"`
}

// GetMeshCoreID returns the node's public key as a MeshCoreID.
func (n *MeshCoreNodeInfo) GetMeshCoreID() meshcore.MeshCoreID {
	var id meshcore.MeshCoreID
	if len(n.PubKey) >= 32 {
		copy(id[:], n.PubKey[:32])
	}
	return id
}

// HasLocation returns true if the node has location information.
func (n *MeshCoreNodeInfo) HasLocation() bool {
	return n.Latitude != nil && n.Longitude != nil
}
