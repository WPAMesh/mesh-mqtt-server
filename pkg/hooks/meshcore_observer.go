package hooks

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/kabili207/meshcore-go/core/codec"

	"github.com/kabili207/mesh-mqtt-server/pkg/config"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
	"github.com/kabili207/mesh-mqtt-server/pkg/store"
)

// MeshCoreObserverHookOptions contains configuration for the observer hook.
type MeshCoreObserverHookOptions struct {
	Server   *mqtt.Server
	Storage  *store.Stores
	Settings config.MeshCoreObserverSettings
	AuthHook *AuthHook
}

// MeshCoreObserverHook ingests MeshCore observer telemetry published in the
// meshcoretomqtt JSON format (as sent by meshcore-room-server). It implements
// ObserverAuthenticator for signature-based auth, ACLChecker to scope observer
// topic access, and OnPublish to decode status and per-packet messages.
type MeshCoreObserverHook struct {
	mqtt.HookBase
	config *MeshCoreObserverHookOptions
}

// observerPacketMessage is the per-packet JSON envelope on the packets topic.
// Numeric fields are strings in the wire format; only the fields we use are
// decoded here. Raw is the hex-encoded full MeshCore frame.
type observerPacketMessage struct {
	Origin   string `json:"origin"`
	OriginID string `json:"origin_id"`
	Type     string `json:"type"`
	Raw      string `json:"raw"`
}

// observerStatusMessage is the heartbeat JSON envelope on the status topic.
type observerStatusMessage struct {
	Status   string `json:"status"` // "online" or "offline"
	Origin   string `json:"origin"`
	OriginID string `json:"origin_id"`
	Model    string `json:"model"`
}

// ID returns the unique identifier for this hook.
func (h *MeshCoreObserverHook) ID() string {
	return "meshcore-observer-hook"
}

// Provides indicates which MQTT events this hook handles.
func (h *MeshCoreObserverHook) Provides(b byte) bool {
	return bytes.Contains([]byte{
		mqtt.OnPublish,
	}, []byte{b})
}

// Init initializes the observer hook.
func (h *MeshCoreObserverHook) Init(config any) error {
	if _, ok := config.(*MeshCoreObserverHookOptions); !ok && config != nil {
		return mqtt.ErrInvalidConfigType
	}
	h.config = config.(*MeshCoreObserverHookOptions)

	if !h.config.Settings.Enabled {
		h.Log.Info("MeshCore observer support is disabled")
		return nil
	}
	if h.config.Settings.TopicPrefix == "" {
		h.config.Settings.TopicPrefix = "meshcore"
	}
	h.Log.Info("MeshCore observer support enabled",
		"topic_prefix", h.config.Settings.TopicPrefix)
	return nil
}

// Stop gracefully stops the observer hook.
func (h *MeshCoreObserverHook) Stop() error {
	h.Log.Info("stopping MeshCore observer hook")
	return nil
}

// IsEnabled returns whether observer support is enabled.
func (h *MeshCoreObserverHook) IsEnabled() bool {
	return h.config != nil && h.config.Settings.Enabled
}

// AuthenticateObserver verifies an observer client's Ed25519-based credentials
// and returns its ClientDetails on success. It satisfies ObserverAuthenticator.
func (h *MeshCoreObserverHook) AuthenticateObserver(cl *mqtt.Client, username, password string) *models.ClientDetails {
	if !h.IsEnabled() {
		return nil
	}

	pubKey, err := observerPubKeyFromUsername(username)
	if err != nil {
		h.Log.Warn("observer auth: bad username", "username", username, "error", err)
		return nil
	}

	if err := verifyObserverPassword(pubKey, password, h.config.Settings.RequireAudience, time.Now()); err != nil {
		h.Log.Warn("observer auth: credential verification failed",
			"username", username, "remote_addr", cl.Net.Remote, "error", err)
		return nil
	}

	return &models.ClientDetails{
		MqttUserName:       username,
		ClientID:           cl.ID,
		Address:            cl.Net.Remote,
		ConnectedAt:        time.Now(),
		IsMeshCoreObserver: true,
		ObserverPubKey:     append([]byte(nil), pubKey...),
		OkToMqttViolations: models.NewOkToMqttWindow(10 * time.Minute),
	}
}

// CheckACL scopes access to the observer topic tree. Observer clients get
// read+write on the whole prefix (they publish their own {IATA}/{PUBKEY}
// subtree). Other authenticated clients, such as mapping tools, get read-only
// access to the observer status/packets topics so they can consume the feed.
// Topics outside the observer tree are left to other checkers.
func (h *MeshCoreObserverHook) CheckACL(cd *models.ClientDetails, topic string, write bool) (bool, bool) {
	prefix := h.config.Settings.TopicPrefix + "/"

	if cd.IsMeshCoreObserver {
		if strings.HasPrefix(topic, prefix) {
			return true, true
		}
		h.Log.Debug("observer client denied access to non-observer topic",
			"client", cd.ClientID, "topic", topic)
		return true, false
	}

	// Non-observer clients (mapping tools) may read the observer feed, matching
	// {prefix}/{IATA}/{PUBKEY}/{packets,status}. They may not write it.
	if isObserverFeedTopic(topic, prefix) {
		if write {
			h.Log.Debug("non-observer client denied write to observer feed",
				"client", cd.ClientID, "topic", topic)
			return true, false
		}
		return true, true
	}

	// Not an observer topic; let other checkers decide.
	return false, false
}

// isObserverFeedTopic reports whether topic matches the observer feed shape
// {prefix}/{IATA}/{PUBKEY}/{packets,status}.
func isObserverFeedTopic(topic, prefix string) bool {
	if !strings.HasPrefix(topic, prefix) {
		return false
	}
	segments := strings.Split(topic[len(prefix):], "/")
	if len(segments) != 3 {
		return false
	}
	return segments[2] == "packets" || segments[2] == "status"
}

// OnPublish decodes observer status and per-packet messages.
func (h *MeshCoreObserverHook) OnPublish(cl *mqtt.Client, pk packets.Packet) (packets.Packet, error) {
	if !h.IsEnabled() {
		return pk, nil
	}

	prefix := h.config.Settings.TopicPrefix + "/"
	if !strings.HasPrefix(pk.TopicName, prefix) {
		return pk, nil
	}

	// Observer topics: {prefix}/{IATA}/{PUBKEY}/{status|packets}
	segments := strings.Split(pk.TopicName[len(prefix):], "/")
	if len(segments) != 3 {
		return pk, nil
	}
	iata, pubKey, kind := segments[0], segments[1], segments[2]
	meshID := iata + "/" + pubKey

	switch kind {
	case "packets":
		h.handlePacketMessage(cl, meshID, pk.Payload)
	case "status":
		h.handleStatusMessage(cl, meshID, pk.Payload)
	}

	return pk, nil
}

// handlePacketMessage decodes a packets-topic envelope and feeds the embedded
// MeshCore frame through the shared advert handling.
func (h *MeshCoreObserverHook) handlePacketMessage(cl *mqtt.Client, meshID string, payload []byte) {
	var msg observerPacketMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		h.Log.Debug("failed to decode observer packet message", "mesh_id", meshID, "error", err)
		return
	}
	if msg.Raw == "" {
		return
	}

	rawData, err := hex.DecodeString(msg.Raw)
	if err != nil {
		h.Log.Debug("failed to decode observer raw frame", "mesh_id", meshID, "error", err)
		return
	}

	var packet codec.Packet
	if err := packet.ReadFrom(rawData); err != nil {
		h.Log.Debug("failed to parse observer MeshCore packet", "mesh_id", meshID, "error", err)
		return
	}

	h.Log.Debug("MeshCore observer packet received",
		"mesh_id", meshID,
		"origin", msg.Origin,
		"route_type", codec.RouteTypeName(packet.RouteType()),
		"payload_type", codec.PayloadTypeName(packet.PayloadType()),
		"path_len", packet.PathLen,
		"payload_len", len(packet.Payload))

	// Resolve the MQTT user ID from the publishing client, if any. Observers
	// authenticate by key and have no DB user, so this is typically nil.
	var userID *int
	if username := string(cl.Properties.Username); username != "" {
		if u, err := h.config.Storage.Users.GetByUserName(username); err == nil && u != nil {
			userID = &u.ID
		}
	}

	switch packet.PayloadType() {
	case codec.PayloadTypeAdvert:
		processMeshCoreAdvert(h.Log, h.config.Storage, h.config.AuthHook, &packet, meshID, cl.ID, userID)
	}
}

// handleStatusMessage logs observer online/offline heartbeats and records the
// observer's reported name on its client for display in the admin view.
func (h *MeshCoreObserverHook) handleStatusMessage(cl *mqtt.Client, meshID string, payload []byte) {
	var msg observerStatusMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		h.Log.Debug("failed to decode observer status message", "mesh_id", meshID, "error", err)
		return
	}

	if msg.Origin != "" && h.config.AuthHook != nil {
		if client := h.config.AuthHook.GetClient(cl.ID); client != nil {
			client.Lock()
			client.ObserverName = msg.Origin
			client.Unlock()
		}
	}

	h.Log.Info("MeshCore observer status",
		"mesh_id", meshID,
		"origin", msg.Origin,
		"origin_id", msg.OriginID,
		"model", msg.Model,
		"status", msg.Status)
}

// processMeshCoreAdvert extracts node info from an ADVERT packet and persists
// it. It is shared by the bridge hook and the observer hook. isDirect (a
// zero-length path) nodes are associated with the publishing user and
// registered on the publishing client for connection tracking.
func processMeshCoreAdvert(log *slog.Logger, storage *store.Stores, authHook *AuthHook, packet *codec.Packet, meshID string, clientID string, userID *int) {
	advert, err := codec.ParseAdvertPayload(packet.Payload)
	if err != nil {
		log.Warn("failed to parse ADVERT payload", "mesh_id", meshID, "error", err)
		return
	}

	isDirect := packet.PathLen == 0

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

	log.Info("MeshCore ADVERT received", logFields...)

	if err := storage.MeshCoreNodes.SaveNode(nodeInfo); err != nil {
		log.Error("failed to save MeshCore node", "pub_key", advert.PubKey[:8], "error", err)
		return
	}

	// Register direct-connect node on its publishing client for connection tracking.
	if isDirect && authHook != nil {
		if client := authHook.GetClient(clientID); client != nil {
			client.AddDirectMCNode(hex.EncodeToString(advert.PubKey[:]))
		}
	}
}

// compile-time interface checks
var (
	_ ObserverAuthenticator = (*MeshCoreObserverHook)(nil)
	_ ACLChecker            = (*MeshCoreObserverHook)(nil)
)
