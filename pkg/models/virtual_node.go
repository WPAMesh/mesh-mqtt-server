package models

import "time"

// VirtualNode represents a bridged identity from another protocol (MeshCore, Matrix, etc.)
// that appears as a Meshtastic node.
type VirtualNode struct {
	// NodeID is the Meshtastic-style node ID (derived from external identity via CRC32)
	NodeID uint32 `db:"node_id"`
	// Source identifies the origin protocol ("meshcore", "matrix", etc.)
	Source string `db:"source"`
	// ExternalID is the protocol-specific identifier (MC pubkey hex, MXID, etc.)
	ExternalID string `db:"external_id"`
	// DisplayName is the cached display name for NODEINFO responses
	DisplayName string `db:"display_name"`
	// FirstSeen is when this virtual node was first created
	FirstSeen time.Time `db:"first_seen"`
	// LastSeen is the last time we received a message from this identity
	LastSeen time.Time `db:"last_seen"`
}

// Virtual node source constants
const (
	VirtualNodeSourceMeshCore = "meshcore"
	VirtualNodeSourceMatrix   = "matrix"
)
