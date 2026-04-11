package hooks

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/kabili207/meshcore-go/core/codec"

	"github.com/kabili207/mesh-mqtt-server/pkg/config"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
	"github.com/kabili207/mesh-mqtt-server/pkg/store"
)

var meshcoreClientRegex = regexp.MustCompile(`^mc-bridge-.+$`)

// MeshCoreHookOptions contains configuration for the MeshCore hook.
type MeshCoreHookOptions struct {
	Server   *mqtt.Server
	Storage  *store.Stores
	Settings config.MeshCoreSettings
	AuthHook *AuthHook
}

// MeshCoreHook handles MeshCore protocol packets received via MQTT.
type MeshCoreHook struct {
	mqtt.HookBase
	config     *MeshCoreHookOptions
	bridgeHook *BridgeHook
}

// SetBridgeHook sets the bridge hook reference for broadcasting virtual node updates.
func (h *MeshCoreHook) SetBridgeHook(bh *BridgeHook) {
	h.bridgeHook = bh
}

// EnrichClient classifies MeshCore clients during authentication.
func (h *MeshCoreHook) EnrichClient(cd *models.ClientDetails, cl *mqtt.Client, user *models.User) bool {
	if meshcoreClientRegex.MatchString(cl.ID) {
		cd.IsMeshCoreClient = true
		return true
	}
	return false
}

// CheckACL handles ACL decisions for MeshCore clients.
func (h *MeshCoreHook) CheckACL(cd *models.ClientDetails, topic string, write bool) (bool, bool) {
	if !cd.IsMeshCoreClient {
		return false, false
	}
	// Check raw-bytes topic (new protocol)
	if h.config.Settings.Topic != "" && topic == h.config.Settings.Topic {
		return true, true
	}
	// Check prefix-based topic (legacy base64 protocol)
	mcPrefix := h.config.Settings.TopicPrefix + "/"
	if strings.HasPrefix(topic, mcPrefix) {
		return true, true
	}
	h.Log.Debug("meshcore client denied access to non-meshcore topic",
		"client", cd.ClientID, "topic", topic)
	return true, false
}

// ID returns the unique identifier for this hook.
func (h *MeshCoreHook) ID() string {
	return "meshcore-hook"
}

// Provides indicates which MQTT events this hook handles.
func (h *MeshCoreHook) Provides(b byte) bool {
	return bytes.Contains([]byte{
		mqtt.OnPublish,
	}, []byte{b})
}

// Init initializes the MeshCore hook with the provided configuration.
func (h *MeshCoreHook) Init(config any) error {
	h.Log.Info("initializing MeshCore hook")

	if _, ok := config.(*MeshCoreHookOptions); !ok && config != nil {
		return mqtt.ErrInvalidConfigType
	}

	h.config = config.(*MeshCoreHookOptions)

	if !h.config.Settings.Enabled {
		h.Log.Info("MeshCore support is disabled")
		return nil
	}

	// Set defaults based on protocol
	if h.config.Settings.Topic != "" {
		h.Log.Info("MeshCore support enabled (raw-bytes protocol)",
			"topic", h.config.Settings.Topic)
	} else {
		// Set default topic prefix for legacy base64 protocol
		if h.config.Settings.TopicPrefix == "" {
			h.config.Settings.TopicPrefix = "meshcore"
		}
		h.Log.Info("MeshCore support enabled (base64 protocol)",
			"topic_prefix", h.config.Settings.TopicPrefix)
	}

	return nil
}

// OnPublish intercepts published packets and processes MeshCore protocol data.
func (h *MeshCoreHook) OnPublish(cl *mqtt.Client, pk packets.Packet) (packets.Packet, error) {
	if !h.config.Settings.Enabled {
		return pk, nil
	}

	var rawData []byte
	var meshID string

	// Check raw-bytes topic (new protocol)
	if h.config.Settings.Topic != "" && pk.TopicName == h.config.Settings.Topic {
		rawData = []byte(pk.Payload)
		meshID = "bridge" // Default mesh ID for raw-bytes protocol
	} else if h.config.Settings.TopicPrefix != "" {
		// Check prefix-based topic (legacy base64 protocol)
		prefix := h.config.Settings.TopicPrefix + "/"
		if !strings.HasPrefix(pk.TopicName, prefix) {
			return pk, nil
		}
		meshID = pk.TopicName[len(prefix):]
		if meshID == "" {
			return pk, nil
		}
		// Decode base64 payload (raw MeshCore packet, not RS232 framed)
		var err error
		rawData, err = base64.StdEncoding.DecodeString(string(pk.Payload))
		if err != nil {
			h.Log.Debug("failed to decode base64 payload",
				"topic", pk.TopicName,
				"error", err)
			return pk, nil
		}
	} else {
		return pk, nil
	}

	// Parse MeshCore packet directly from decoded bytes
	var packet codec.Packet
	if err := packet.ReadFrom(rawData); err != nil {
		h.Log.Debug("failed to parse MeshCore packet",
			"topic", pk.TopicName,
			"mesh_id", meshID,
			"error", err)
		return pk, nil
	}

	// Log packet summary
	h.Log.Debug("MeshCore packet received",
		"mesh_id", meshID,
		"route_type", codec.RouteTypeName(packet.RouteType()),
		"payload_type", codec.PayloadTypeName(packet.PayloadType()),
		"path_len", packet.PathLen,
		"payload_len", len(packet.Payload))

	// Resolve the MQTT user ID from the publishing client
	var userID *int
	if username := string(cl.Properties.Username); username != "" {
		if u, err := h.config.Storage.Users.GetByUserName(username); err == nil && u != nil {
			userID = &u.ID
		}
	}

	// Process specific payload types
	switch packet.PayloadType() {
	case codec.PayloadTypeAdvert:
		h.processAdvert(&packet, meshID, cl.ID, userID)
	}

	// Pass through unmodified
	return pk, nil
}

// processAdvert handles ADVERT payloads by extracting node info and saving to database.
func (h *MeshCoreHook) processAdvert(packet *codec.Packet, meshID string, clientID string, userID *int) {
	advert, err := codec.ParseAdvertPayload(packet.Payload)
	if err != nil {
		h.Log.Warn("failed to parse ADVERT payload",
			"mesh_id", meshID,
			"error", err)
		return
	}

	isDirect := packet.PathLen == 0

	// Build log fields
	logFields := []any{
		"mesh_id", meshID,
		"pub_key", advert.PubKey[:8], // First 8 bytes for brevity
		"timestamp", advert.Timestamp,
		"is_direct", isDirect,
	}

	// Only associate user ID with direct-connect nodes, since non-direct
	// nodes may be heard by multiple bridges with different users.
	var nodeUserID *int
	if isDirect {
		nodeUserID = userID
	}

	// Extract node info from appdata if present
	nodeInfo := &models.MeshCoreNodeInfo{
		PubKey:   advert.PubKey[:],
		IsDirect: isDirect,
		UserID:   nodeUserID,
	}
	now := time.Now()
	nodeInfo.LastSeen = &now

	if advert.AppData != nil {
		nodeInfo.NodeType = int16(advert.AppData.NodeType)
		nodeInfo.Name = advert.AppData.Name
		nodeInfo.Latitude = advert.AppData.Lat
		nodeInfo.Longitude = advert.AppData.Lon

		logFields = append(logFields,
			"node_type", codec.NodeTypeName(advert.AppData.NodeType),
			"name", advert.AppData.Name)

		if advert.AppData.HasLocation() {
			logFields = append(logFields,
				"lat", *advert.AppData.Lat,
				"lon", *advert.AppData.Lon)
		}
	}

	h.Log.Info("MeshCore ADVERT received", logFields...)

	// Save to database
	if err := h.config.Storage.MeshCoreNodes.SaveNode(nodeInfo); err != nil {
		h.Log.Error("failed to save MeshCore node",
			"pub_key", advert.PubKey[:8],
			"error", err)
		return
	}

	// Register direct-connect node on its MeshCore client for connection tracking
	if isDirect && h.config.AuthHook != nil {
		if meshcoreClient := h.config.AuthHook.GetClient(clientID); meshcoreClient != nil {
			meshcoreClient.AddDirectMCNode(hex.EncodeToString(advert.PubKey[:]))
		}
	}

	// Update virtual node display name if one exists for this pubkey
	h.syncVirtualNode(nodeInfo)
}

// syncVirtualNode updates the display name of a virtual node if one exists for this
// MeshCore pubkey and the name has changed.
func (h *MeshCoreHook) syncVirtualNode(nodeInfo *models.MeshCoreNodeInfo) {
	if h.config.Storage == nil || nodeInfo.Name == "" {
		return
	}

	virtualNodeID := MCPubKeyToNodeID(nodeInfo.PubKey)
	existingNode, err := h.config.Storage.VirtualNodes.GetByNodeID(virtualNodeID)
	if err != nil {
		h.Log.Warn("failed to look up virtual node for advert sync", "error", err)
		return
	}
	if existingNode == nil {
		return // No virtual node yet — will be created when they send a message
	}

	if existingNode.DisplayName == nodeInfo.Name {
		return // Already up to date
	}

	oldName := existingNode.DisplayName
	existingNode.DisplayName = nodeInfo.Name
	existingNode.LastSeen = time.Now()
	if err := h.config.Storage.VirtualNodes.Save(existingNode); err != nil {
		h.Log.Warn("failed to update virtual node from advert",
			"node_id", virtualNodeID,
			"error", err)
		return
	}

	h.Log.Info("updated virtual node display name from advert",
		"node_id", virtualNodeID,
		"old_name", oldName,
		"new_name", nodeInfo.Name)

	// Broadcast updated NODEINFO to Meshtastic so clients learn the new name
	if h.bridgeHook != nil && h.bridgeHook.IsEnabled() {
		h.bridgeHook.BroadcastVirtualNodeUpdate(virtualNodeID, nodeInfo.Name)
	}
}

// Stop gracefully stops the MeshCore hook.
func (h *MeshCoreHook) Stop() error {
	h.Log.Info("stopping MeshCore hook")
	return nil
}

// IsEnabled returns whether MeshCore support is enabled.
func (h *MeshCoreHook) IsEnabled() bool {
	return h.config != nil && h.config.Settings.Enabled
}
