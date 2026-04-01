package hooks

import (
	"sync"
	"time"
)

const (
	ringSize          = 64
	cleanupInterval   = 5 * time.Minute
)

// RateLimitConfig holds per-node rate limiting parameters.
type RateLimitConfig struct {
	MaxPackets int
	Window     time.Duration
}

type packetEntry struct {
	packetID  uint32
	timestamp time.Time
}

// nodeWindow tracks recent unique packets from a single mesh node.
type nodeWindow struct {
	packets [ringSize]packetEntry
	pos     int
	count   int
	seen    map[uint32]struct{}
}

// NodeRateLimiter enforces per-node packet rate limits while allowing
// duplicate packets (same packet ID from different gateways) through.
type NodeRateLimiter struct {
	mu    sync.Mutex
	nodes map[uint32]*nodeWindow
	cfg   RateLimitConfig
	stop  chan struct{}
}

func NewNodeRateLimiter(cfg RateLimitConfig) *NodeRateLimiter {
	return &NodeRateLimiter{
		nodes: make(map[uint32]*nodeWindow),
		cfg:   cfg,
		stop:  make(chan struct{}),
	}
}

// Start begins the background cleanup goroutine.
func (r *NodeRateLimiter) Start() {
	go r.cleanupLoop()
}

// Stop shuts down the background cleanup goroutine.
func (r *NodeRateLimiter) Stop() {
	close(r.stop)
}

// AllowPacket returns true if the packet should be forwarded.
// Duplicate packets (same packetID from the same source node, arriving via
// different gateways) are always allowed without counting toward the limit.
func (r *NodeRateLimiter) AllowPacket(nodeFrom, packetID uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	w := r.nodes[nodeFrom]
	if w == nil {
		w = &nodeWindow{
			seen: make(map[uint32]struct{}),
		}
		r.nodes[nodeFrom] = w
	}

	// Duplicate from another gateway: allow without counting
	if _, dup := w.seen[packetID]; dup {
		return true
	}

	// Count unique packets within the window
	now := time.Now()
	cutoff := now.Add(-r.cfg.Window)
	active := 0
	limit := w.count
	if limit > ringSize {
		limit = ringSize
	}
	for i := range limit {
		if w.packets[i].timestamp.After(cutoff) {
			active++
		}
	}

	if active >= r.cfg.MaxPackets {
		return false
	}

	// Record the new packet, evicting the oldest entry from the ring buffer
	old := w.packets[w.pos]
	if old.packetID != 0 || !old.timestamp.IsZero() {
		delete(w.seen, old.packetID)
	}
	w.packets[w.pos] = packetEntry{packetID: packetID, timestamp: now}
	w.seen[packetID] = struct{}{}
	w.pos = (w.pos + 1) % ringSize
	if w.count < ringSize {
		w.count++
	}

	return true
}

// cleanupLoop periodically removes stale node entries to bound memory usage.
func (r *NodeRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.cleanup()
		}
	}
}

func (r *NodeRateLimiter) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().Add(-r.cfg.Window)
	for nodeID, w := range r.nodes {
		hasActive := false
		limit := w.count
		if limit > ringSize {
			limit = ringSize
		}
		for i := range limit {
			if w.packets[i].timestamp.After(cutoff) {
				hasActive = true
				break
			}
		}
		if !hasActive {
			delete(r.nodes, nodeID)
		}
	}
}
