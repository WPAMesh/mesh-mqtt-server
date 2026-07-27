package hooks

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"strings"

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
	config *MeshCoreHookOptions
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
func (h *MeshCoreHook) CheckACL(cd *models.ClientDetails, cl *mqtt.Client, topic string, write bool) (bool, bool) {
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
		// The legacy bridge protocol uses a single-segment mesh ID
		// ({prefix}/{mesh_id}). Topics with further segments belong to another
		// scheme (e.g. the observer feed {prefix}/{IATA}/{PUBKEY}/{status,packets})
		// and must not be treated as base64 bridge packets.
		if strings.Contains(meshID, "/") {
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
	processMeshCoreAdvert(h.Log, h.config.Storage, h.config.AuthHook, packet, meshID, clientID, userID)
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
