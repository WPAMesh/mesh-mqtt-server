package hooks

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"regexp"
	"sync"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
	"google.golang.org/protobuf/proto"

	"github.com/kabili207/mesh-mqtt-server/pkg/config"
	"github.com/kabili207/mesh-mqtt-server/pkg/meshcore/codec"
	pb "github.com/kabili207/mesh-mqtt-server/pkg/meshtastic/generated"
	"github.com/kabili207/mesh-mqtt-server/pkg/meshtastic/radio"
	"github.com/kabili207/mesh-mqtt-server/pkg/store"
)

const (
	// Fingerprint cache TTL
	fingerprintTTL = 30 * time.Second
	// Maximum message length for bridging
	maxBridgeMessageLen = 200
)

var (
	// Regex to match Meshtastic channel topics: msh/{root}/2/e/{channel}/{gateway}
	meshtasticTopicRegex = regexp.MustCompile(`^(msh(?:/[^/]+)*)/2/e/([^/]+)/(![a-f0-9]{8})$`)
	// Regex to match MeshCore topics: meshcore/{mesh_id}/rx or /tx
	meshCoreTopicRegex = regexp.MustCompile(`^meshcore/([^/]+)/(rx|tx)$`)
)

// BridgeHookOptions contains configuration for the bridge hook.
type BridgeHookOptions struct {
	Server       *mqtt.Server
	MeshSettings config.MeshSettings
	Bridge       config.BridgeSettings
	Storage      *store.Stores
}

// channelMappingIndex holds parsed and indexed channel mapping data.
type channelMappingIndex struct {
	mapping         *config.ChannelMapping
	meshCoreKey     []byte // Parsed MeshCore channel key
	meshCoreHash    uint8  // First byte of SHA256(key)
	meshtasticKey   []byte // Meshtastic PSK for this channel
	meshtasticHash  uint32 // Meshtastic channel hash
}

// BridgeHook handles bidirectional bridging between Meshtastic and MeshCore.
type BridgeHook struct {
	mqtt.HookBase
	config *BridgeHookOptions

	// Indexed mappings for fast lookup
	mtMappings map[string]*channelMappingIndex // by "root/channel" key
	mcMappings map[uint8][]*channelMappingIndex // by MeshCore channel hash (may have collisions)

	// Loop prevention
	fingerprints    map[[32]byte]time.Time
	fingerprintLock sync.RWMutex

	// Identity caches for loop detection
	mtNodeNames     map[uint32]string      // Meshtastic NodeID -> name (for detecting bridged MC messages)
	mcNodeNames     map[string]string      // MeshCore pubkey hex prefix -> name (for detecting bridged MT messages)
	nodeNameLock    sync.RWMutex

	// Packet ID counter for Meshtastic packets
	packetIDCounter uint32
	packetIDLock    sync.Mutex

	// Stop channel
	stopChan chan struct{}
}

// ID returns the unique identifier for this hook.
func (h *BridgeHook) ID() string {
	return "bridge-hook"
}

// Provides indicates which MQTT events this hook handles.
func (h *BridgeHook) Provides(b byte) bool {
	return bytes.Contains([]byte{
		mqtt.OnPublish,
	}, []byte{b})
}

// Init initializes the bridge hook with the provided configuration.
func (h *BridgeHook) Init(config any) error {
	h.Log.Info("initializing bridge hook")

	if _, ok := config.(*BridgeHookOptions); !ok && config != nil {
		return mqtt.ErrInvalidConfigType
	}

	h.config = config.(*BridgeHookOptions)
	h.mtMappings = make(map[string]*channelMappingIndex)
	h.mcMappings = make(map[uint8][]*channelMappingIndex)
	h.fingerprints = make(map[[32]byte]time.Time)
	h.mtNodeNames = make(map[uint32]string)
	h.mcNodeNames = make(map[string]string)
	h.stopChan = make(chan struct{})

	if !h.config.Bridge.Enabled {
		h.Log.Info("bridge is disabled")
		return nil
	}

	// Parse and index channel mappings
	for i := range h.config.Bridge.ChannelMappings {
		mapping := &h.config.Bridge.ChannelMappings[i]

		idx := &channelMappingIndex{
			mapping: mapping,
		}

		// Parse MeshCore channel key
		mcKey, err := radio.ParseKey(mapping.MeshCoreChannelKey)
		if err != nil {
			h.Log.Error("failed to parse MeshCore channel key",
				"meshtastic_channel", mapping.MeshtasticChannel,
				"error", err)
			continue
		}
		idx.meshCoreKey = mcKey
		idx.meshCoreHash = ComputeChannelHash(mcKey)

		// Get Meshtastic PSK for the channel
		mtKey := h.getMeshtasticKey(mapping.MeshtasticChannel)
		if mtKey == nil {
			h.Log.Error("meshtastic channel not found in config",
				"channel", mapping.MeshtasticChannel)
			continue
		}
		idx.meshtasticKey = mtKey
		mtHash, _ := radio.ChannelHash(mapping.MeshtasticChannel, mtKey)
		idx.meshtasticHash = mtHash

		// Index by Meshtastic topic root + channel
		mtKey_ := mapping.MeshtasticTopicRoot + "/" + mapping.MeshtasticChannel
		h.mtMappings[mtKey_] = idx

		// Index by MeshCore channel hash (handle collisions)
		h.mcMappings[idx.meshCoreHash] = append(h.mcMappings[idx.meshCoreHash], idx)

		h.Log.Info("bridge mapping configured",
			"meshtastic_channel", mapping.MeshtasticChannel,
			"meshtastic_root", mapping.MeshtasticTopicRoot,
			"meshcore_mesh_id", mapping.MeshCoreMeshID,
			"meshcore_hash", idx.meshCoreHash,
			"direction", mapping.Direction)
	}

	// Start fingerprint cleanup goroutine
	go h.cleanupFingerprints()

	// Load existing node names from storage for loop detection
	h.loadNodeNamesFromStorage()

	h.Log.Info("bridge enabled",
		"mappings", len(h.config.Bridge.ChannelMappings),
		"meshtastic_prefix", h.config.Bridge.MeshtasticPrefix,
		"meshcore_prefix", h.config.Bridge.MeshCorePrefix)

	return nil
}

// loadNodeNamesFromStorage loads known node names from the database.
func (h *BridgeHook) loadNodeNamesFromStorage() {
	if h.config.Storage == nil {
		return
	}

	// Load Meshtastic nodes
	mtNodes, err := h.config.Storage.NodeDB.GetAllNodes()
	if err != nil {
		h.Log.Warn("failed to load Meshtastic nodes for bridge", "error", err)
	} else {
		h.nodeNameLock.Lock()
		for _, node := range mtNodes {
			if node.LongName != "" {
				h.mtNodeNames[uint32(node.NodeID)] = node.LongName
			}
		}
		h.nodeNameLock.Unlock()
		h.Log.Debug("loaded Meshtastic node names", "count", len(mtNodes))
	}

	// Load MeshCore nodes
	mcNodes, err := h.config.Storage.MeshCoreNodes.GetAllNodes()
	if err != nil {
		h.Log.Warn("failed to load MeshCore nodes for bridge", "error", err)
	} else {
		h.nodeNameLock.Lock()
		for _, node := range mcNodes {
			if node.Name != "" && len(node.PubKey) >= 8 {
				// Use first 8 bytes of pubkey as hex prefix for lookup
				prefix := fmt.Sprintf("%x", node.PubKey[:8])
				h.mcNodeNames[prefix] = node.Name
			}
		}
		h.nodeNameLock.Unlock()
		h.Log.Debug("loaded MeshCore node names", "count", len(mcNodes))
	}
}

// updateMeshtasticNodeName updates the cache with a Meshtastic node's name.
func (h *BridgeHook) updateMeshtasticNodeName(nodeID uint32, name string) {
	if name == "" {
		return
	}
	h.nodeNameLock.Lock()
	h.mtNodeNames[nodeID] = name
	h.nodeNameLock.Unlock()
}

// getMeshtasticNodeName looks up a node name by Meshtastic NodeID.
func (h *BridgeHook) getMeshtasticNodeName(nodeID uint32) string {
	h.nodeNameLock.RLock()
	name := h.mtNodeNames[nodeID]
	h.nodeNameLock.RUnlock()

	if name != "" {
		return name
	}

	// Try loading from storage
	if h.config.Storage != nil {
		// Try with user ID 0 first (anonymous)
		node, err := h.config.Storage.NodeDB.GetNode(nodeID, 0)
		if err == nil && node != nil && node.LongName != "" {
			h.updateMeshtasticNodeName(nodeID, node.LongName)
			return node.LongName
		}
	}

	return ""
}

// isKnownMeshtasticName checks if a name belongs to a known Meshtastic node.
func (h *BridgeHook) isKnownMeshtasticName(name string) bool {
	h.nodeNameLock.RLock()
	defer h.nodeNameLock.RUnlock()

	for _, nodeName := range h.mtNodeNames {
		if nodeName == name {
			return true
		}
	}
	return false
}

// isKnownMeshCoreName checks if a name belongs to a known MeshCore node.
func (h *BridgeHook) isKnownMeshCoreName(name string) bool {
	h.nodeNameLock.RLock()
	defer h.nodeNameLock.RUnlock()

	for _, nodeName := range h.mcNodeNames {
		if nodeName == name {
			return true
		}
	}
	return false
}

// getMeshtasticKey returns the PSK for a Meshtastic channel from config.
func (h *BridgeHook) getMeshtasticKey(channelName string) []byte {
	for _, ch := range h.config.MeshSettings.Channels {
		if ch.Name == channelName {
			if ch.Key == "" {
				return radio.DefaultKey
			}
			key, err := radio.ParseKey(ch.Key)
			if err != nil {
				return nil
			}
			return key
		}
	}
	// Default to LongFast with default key
	if channelName == "LongFast" || channelName == "LongSlow" || channelName == "VLongSlow" {
		return radio.DefaultKey
	}
	return nil
}

// cleanupFingerprints periodically removes expired fingerprints.
func (h *BridgeHook) cleanupFingerprints() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.fingerprintLock.Lock()
			now := time.Now()
			for fp, expiry := range h.fingerprints {
				if now.After(expiry) {
					delete(h.fingerprints, fp)
				}
			}
			h.fingerprintLock.Unlock()
		case <-h.stopChan:
			return
		}
	}
}

// computeFingerprint creates a fingerprint for loop detection.
func computeFingerprint(text, channel, protocol string) [32]byte {
	data := text + "|" + channel + "|" + protocol
	return sha256.Sum256([]byte(data))
}

// checkAndAddFingerprint returns true if the fingerprint already exists (loop detected).
func (h *BridgeHook) checkAndAddFingerprint(fp [32]byte) bool {
	h.fingerprintLock.Lock()
	defer h.fingerprintLock.Unlock()

	if _, exists := h.fingerprints[fp]; exists {
		return true // Loop detected
	}

	h.fingerprints[fp] = time.Now().Add(fingerprintTTL)
	return false
}

// OnPublish intercepts published packets and bridges between protocols.
func (h *BridgeHook) OnPublish(cl *mqtt.Client, pk packets.Packet) (packets.Packet, error) {
	if !h.config.Bridge.Enabled {
		return pk, nil
	}

	// Try Meshtastic topic
	if matches := meshtasticTopicRegex.FindStringSubmatch(pk.TopicName); len(matches) > 0 {
		h.handleMeshtasticMessage(pk, matches[1], matches[2], matches[3])
		return pk, nil
	}

	// Try MeshCore topic
	if matches := meshCoreTopicRegex.FindStringSubmatch(pk.TopicName); len(matches) > 0 {
		if matches[2] == "rx" { // Only bridge received messages
			h.handleMeshCoreMessage(pk, matches[1])
		}
		return pk, nil
	}

	return pk, nil
}

// handleMeshtasticMessage processes a Meshtastic message and bridges to MeshCore.
func (h *BridgeHook) handleMeshtasticMessage(pk packets.Packet, topicRoot, channel, gateway string) {
	// Look up mapping
	mappingKey := topicRoot + "/" + channel
	idx, ok := h.mtMappings[mappingKey]
	if !ok {
		return // No mapping for this channel
	}

	// Check direction
	if idx.mapping.Direction != "both" && idx.mapping.Direction != "mt_to_mc" {
		return
	}

	// Skip if from bridge's own gateway (loop prevention)
	selfGateway := h.config.MeshSettings.SelfNode.NodeID.String()
	if gateway == selfGateway {
		return
	}

	// Decode ServiceEnvelope
	var env pb.ServiceEnvelope
	if err := proto.Unmarshal(pk.Payload, &env); err != nil {
		h.Log.Debug("failed to decode ServiceEnvelope", "error", err)
		return
	}

	packet := env.GetPacket()
	if packet == nil {
		return
	}

	// Decrypt the packet
	data, err := radio.TryDecode(packet, idx.meshtasticKey)
	if err != nil {
		h.Log.Debug("failed to decrypt Meshtastic packet", "error", err)
		return
	}

	// Only bridge text messages
	if data.Portnum != pb.PortNum_TEXT_MESSAGE_APP {
		return
	}

	text := string(data.Payload)
	if text == "" {
		return
	}

	// Loop prevention: check prefix
	if HasBridgePrefix(text, h.config.Bridge.MeshtasticPrefix, h.config.Bridge.MeshCorePrefix) {
		return
	}

	// Loop prevention: check fingerprint
	fp := computeFingerprint(text, channel, "meshtastic")
	if h.checkAndAddFingerprint(fp) {
		return
	}

	// Get sender name from NodeDB
	senderName := h.getMeshtasticNodeName(packet.From)
	if senderName == "" {
		// Use default name based on node ID
		senderName = fmt.Sprintf("!%08x", packet.From)
	}

	// Update cache with this sender
	h.updateMeshtasticNodeName(packet.From, senderName)

	// Format message for MeshCore
	formattedMsg := FormatMeshtasticToMeshCore(senderName, text, h.config.Bridge.MeshtasticPrefix)
	formattedMsg = TruncateMessage(formattedMsg, maxBridgeMessageLen)

	// Build and send MeshCore packet
	h.sendToMeshCore(idx, formattedMsg, channel)
}

// handleMeshCoreMessage processes a MeshCore message and bridges to Meshtastic.
func (h *BridgeHook) handleMeshCoreMessage(pk packets.Packet, meshID string) {
	// Decode base64 payload
	rawData, err := base64.StdEncoding.DecodeString(string(pk.Payload))
	if err != nil {
		h.Log.Debug("failed to decode base64 payload", "error", err)
		return
	}

	// Decode RS232 frame
	frame, _, err := codec.DecodeRS232Frame(rawData)
	if err != nil {
		h.Log.Debug("failed to decode RS232 frame", "error", err)
		return
	}

	// Parse MeshCore packet
	var mcPacket codec.Packet
	if err := mcPacket.ReadFrom(frame.Payload); err != nil {
		h.Log.Debug("failed to parse MeshCore packet", "error", err)
		return
	}

	// Only bridge GRP_TXT messages
	if mcPacket.PayloadType() != codec.PayloadTypeGrpTxt {
		return
	}

	// Parse group payload
	grpPayload, err := codec.ParseGroupPayload(mcPacket.Payload)
	if err != nil {
		h.Log.Debug("failed to parse group payload", "error", err)
		return
	}

	// Find matching channel mappings by hash
	mappings, ok := h.mcMappings[grpPayload.ChannelHash]
	if !ok || len(mappings) == 0 {
		return
	}

	// Try each mapping with matching hash (handle collisions)
	for _, idx := range mappings {
		// Check mesh ID matches
		if idx.mapping.MeshCoreMeshID != meshID {
			continue
		}

		// Check direction
		if idx.mapping.Direction != "both" && idx.mapping.Direction != "mc_to_mt" {
			continue
		}

		// Try to decrypt
		ciphertextWithMAC := make([]byte, len(grpPayload.Ciphertext)+meshCoreCipherMACSize)
		binary.LittleEndian.PutUint16(ciphertextWithMAC[0:2], grpPayload.MAC)
		copy(ciphertextWithMAC[meshCoreCipherMACSize:], grpPayload.Ciphertext)

		plaintext, err := DecryptGroupMessage(ciphertextWithMAC, idx.meshCoreKey)
		if err != nil {
			h.Log.Debug("failed to decrypt MeshCore message", "error", err)
			continue
		}

		// Parse the plaintext
		_, txtType, message, err := ParseGrpTxtPlaintext(plaintext)
		if err != nil {
			h.Log.Debug("failed to parse GRP_TXT plaintext", "error", err)
			continue
		}

		// Only bridge plain text messages
		if txtType != 0 {
			continue
		}

		if message == "" {
			continue
		}

		// Loop prevention: check prefix
		if HasBridgePrefix(message, h.config.Bridge.MeshtasticPrefix, h.config.Bridge.MeshCorePrefix) {
			return
		}

		// Loop prevention: check if sender name matches a known Meshtastic node
		// This catches messages that were bridged MT→MC and are now coming back
		sender, _, hasSender := ParseSenderFromMessage(message)
		if hasSender && h.isKnownMeshtasticName(sender) {
			h.Log.Debug("ignoring message from known Meshtastic node (loop prevention)",
				"sender", sender)
			return
		}

		// Loop prevention: check fingerprint
		fp := computeFingerprint(message, idx.mapping.MeshtasticChannel, "meshcore")
		if h.checkAndAddFingerprint(fp) {
			return
		}

		// Format message for Meshtastic
		formattedMsg, _ := FormatMeshCoreToMeshtastic(message, h.config.Bridge.MeshCorePrefix, h.config.Bridge.ParseSenderName)
		formattedMsg = TruncateMessage(formattedMsg, maxBridgeMessageLen)

		// Send to Meshtastic
		h.sendToMeshtastic(idx, formattedMsg)
		return // Only send once even if multiple mappings match
	}
}

// sendToMeshCore sends a message to MeshCore.
func (h *BridgeHook) sendToMeshCore(idx *channelMappingIndex, message, channel string) {
	timestamp := uint32(time.Now().Unix())

	// Build plaintext
	plaintext := BuildGrpTxtPlaintext(timestamp, message)

	// Encrypt
	encrypted, err := EncryptGroupMessage(plaintext, idx.meshCoreKey)
	if err != nil {
		h.Log.Error("failed to encrypt MeshCore message", "error", err)
		return
	}

	// Build MeshCore packet
	mcPacket := codec.Packet{
		Header:  (codec.PayloadTypeGrpTxt << codec.PHTypeShift) | codec.RouteTypeFlood,
		PathLen: 0,
		Path:    nil,
	}

	// Build payload: channel_hash(1) + MAC(2) + ciphertext
	payload := make([]byte, 1+len(encrypted))
	payload[0] = idx.meshCoreHash
	copy(payload[1:], encrypted)
	mcPacket.Payload = payload

	// Encode packet
	packetBytes := mcPacket.WriteTo()

	// Encode RS232 frame
	frameBytes, err := codec.EncodeRS232Frame(packetBytes)
	if err != nil {
		h.Log.Error("failed to encode RS232 frame", "error", err)
		return
	}

	// Base64 encode
	b64Payload := base64.StdEncoding.EncodeToString(frameBytes)

	// Publish to MeshCore tx topic
	topic := "meshcore/" + idx.mapping.MeshCoreMeshID + "/tx"

	go func(t string, payload string) {
		err := h.config.Server.Publish(t, []byte(payload), false, 0)
		if err != nil {
			h.Log.Error("failed to publish to MeshCore", "error", err, "topic", t)
		} else {
			h.Log.Debug("bridged message to MeshCore",
				"topic", t,
				"channel", channel,
				"message_len", len(message))
		}
	}(topic, b64Payload)

	// Also add fingerprint for the sent message to prevent loop on echo
	fp := computeFingerprint(message, channel, "meshcore")
	h.checkAndAddFingerprint(fp)
}

// sendToMeshtastic sends a message to Meshtastic.
func (h *BridgeHook) sendToMeshtastic(idx *channelMappingIndex, message string) {
	// Build Meshtastic Data payload
	bitfield := uint32(BITFIELD_OkToMQTT)
	data := pb.Data{
		Portnum:  pb.PortNum_TEXT_MESSAGE_APP,
		Payload:  []byte(message),
		Bitfield: &bitfield,
	}

	rawData, err := proto.Marshal(&data)
	if err != nil {
		h.Log.Error("failed to marshal Meshtastic data", "error", err)
		return
	}

	// Encrypt
	packetID := h.generatePacketID()
	fromNode := uint32(h.config.MeshSettings.SelfNode.NodeID)

	encrypted, err := radio.XOR(rawData, idx.meshtasticKey, packetID, fromNode)
	if err != nil {
		h.Log.Error("failed to encrypt Meshtastic packet", "error", err)
		return
	}

	// Build MeshPacket
	msgTime := uint32(time.Now().Unix())
	pkt := pb.MeshPacket{
		Id:       packetID,
		To:       uint32(0xFFFFFFFF), // Broadcast
		From:     fromNode,
		HopLimit: 0,
		HopStart: 0,
		ViaMqtt:  true,
		RxTime:   msgTime,
		Channel:  idx.meshtasticHash,
		Priority: pb.MeshPacket_DEFAULT,
		Delayed:  pb.MeshPacket_NO_DELAY,
		PayloadVariant: &pb.MeshPacket_Encrypted{
			Encrypted: encrypted,
		},
	}

	// Build ServiceEnvelope
	env := pb.ServiceEnvelope{
		ChannelId: idx.mapping.MeshtasticChannel,
		GatewayId: h.config.MeshSettings.SelfNode.NodeID.String(),
		Packet:    &pkt,
	}

	rawEnv, err := proto.Marshal(&env)
	if err != nil {
		h.Log.Error("failed to marshal ServiceEnvelope", "error", err)
		return
	}

	// Publish to Meshtastic topic
	topic := idx.mapping.MeshtasticTopicRoot + "/2/e/" + idx.mapping.MeshtasticChannel + "/" + h.config.MeshSettings.SelfNode.NodeID.String()

	go func(t string, payload []byte) {
		// Small delay to allow radio switching
		time.Sleep(200 * time.Millisecond)

		err := h.config.Server.Publish(t, payload, false, 0)
		if err != nil {
			h.Log.Error("failed to publish to Meshtastic", "error", err, "topic", t)
		} else {
			h.Log.Debug("bridged message to Meshtastic",
				"topic", t,
				"channel", idx.mapping.MeshtasticChannel,
				"message_len", len(message))
		}
	}(topic, rawEnv)

	// Also add fingerprint for the sent message to prevent loop on echo
	fp := computeFingerprint(message, idx.mapping.MeshtasticChannel, "meshtastic")
	h.checkAndAddFingerprint(fp)
}

// generatePacketID generates a unique packet ID.
func (h *BridgeHook) generatePacketID() uint32 {
	h.packetIDLock.Lock()
	defer h.packetIDLock.Unlock()

	h.packetIDCounter++
	// Mix in some randomness like the Meshtastic firmware does
	h.packetIDCounter = (h.packetIDCounter & 0x3FF) | (uint32(time.Now().UnixNano()&0x3FFFFF) << 10)
	return h.packetIDCounter
}

// Stop gracefully stops the bridge hook.
func (h *BridgeHook) Stop() error {
	h.Log.Info("stopping bridge hook")
	close(h.stopChan)
	return nil
}

// IsEnabled returns whether bridging is enabled.
func (h *BridgeHook) IsEnabled() bool {
	return h.config != nil && h.config.Bridge.Enabled
}
