package meshtastic

import (
	"fmt"
	"strconv"
	"strings"
)

const (

	// Node ID used for broadcasting
	BROADCAST_ID uint32 = 0xffffffff
	// Node ID used for broadcasting exclusively over MQTT or BLE mesh
	BROADCAST_ID_NO_LORA uint32 = 1

	// The maximum allowed number of hops. The bridge consumes one hop
	// when relaying messages, so the functional limit is one less
	MAX_HOPS = 7
)

type NodeID uint32

func (n NodeID) String() string {
	switch uint32(n) {
	case BROADCAST_ID:
		return "^all"
	case BROADCAST_ID_NO_LORA:
		return "^no-lora"
	default:
		return fmt.Sprintf("!%08x", uint32(n))
	}
}

// GetNodeColor returns the RGB values used by various user-interfaces
func (n NodeID) GetNodeColor() (r, g, b uint8) {
	r = uint8((n & 0xFF0000) >> 16)
	g = uint8((n & 0x00FF00) >> 8)
	b = uint8(n & 0x0000FF)
	return
}

// GetDefaultNodeNames returns the default long and short name for an unnamed node
func (n NodeID) GetDefaultNodeNames() (longName, shortName string) {
	name := n.String()
	shortName = name[len(name)-4:]
	longName = fmt.Sprintf("Meshtastic %s", shortName)
	return
}

func ParseNodeID(nodeID string) (NodeID, error) {
	if nodeID == "^all" {
		return NodeID(BROADCAST_ID), nil
	}
	if nodeID == "^no-lora" {
		return NodeID(BROADCAST_ID_NO_LORA), nil
	}
	v, _ := strings.CutPrefix(nodeID, "!")
	packet64, err := strconv.ParseUint(string(v), 16, 32)
	if err != nil {
		return NodeID(uint32(0)), err
	}
	return NodeID(uint32(packet64)), nil
}
