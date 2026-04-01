package models

import "time"

type BlockedNode struct {
	NodeID    uint32    `db:"node_id" json:"node_id"`
	Reason    string    `db:"reason" json:"reason"`
	BlockedAt time.Time `db:"blocked_at" json:"blocked_at"`
	BlockedBy *int      `db:"blocked_by" json:"blocked_by,omitempty"`
}
