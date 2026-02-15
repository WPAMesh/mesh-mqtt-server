package hooks

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"regexp"
	"sync"
	"time"

	"filippo.io/edwards25519"
	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
	"google.golang.org/protobuf/proto"

	"github.com/kabili207/mesh-mqtt-server/pkg/config"
	"github.com/kabili207/mesh-mqtt-server/pkg/meshcore/codec"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
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

	// MeshCore topic matching (built from config prefix)
	mcTopicRegex  *regexp.Regexp
	mcTopicPrefix string // e.g. "meshcore"

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

	// Set up MeshCore topic prefix and regex
	h.mcTopicPrefix = h.config.Bridge.TopicPrefix
	if h.mcTopicPrefix == "" {
		h.mcTopicPrefix = "meshcore"
	}
	h.mcTopicRegex = regexp.MustCompile(`^` + regexp.QuoteMeta(h.mcTopicPrefix) + `/([^/]+)$`)

	// Parse and index channel mappings
	for i := range h.config.Bridge.ChannelMappings {
		mapping := &h.config.Bridge.ChannelMappings[i]

		idx := &channelMappingIndex{
			mapping: mapping,
		}

		// Parse MeshCore channel key
		mcKey, err := crypto.ParseKey(mapping.MeshCoreChannelKey)
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
		mtHash, _ := crypto.ChannelHash(mapping.MeshtasticChannel, mtKey)
		idx.meshtasticHash = mtHash

		// Index by Meshtastic topic root + channel
		mtKey_ := mapping.MeshtasticTopicRoot + "/" + mapping.MeshtasticChannel
		h.mtMappings[mtKey_] = idx

		// Index by MeshCore channel hash (handle collisions)
		h.mcMappings[idx.meshCoreHash] = append(h.mcMappings[idx.meshCoreHash], idx)

		h.Log.Info("bridge mapping configured",
			"meshtastic_channel", mapping.MeshtasticChannel,
			"meshtastic_root", mapping.MeshtasticTopicRoot,
			"meshcore_hash", idx.meshCoreHash,
			"direction", mapping.Direction)
	}

	// Start fingerprint cleanup goroutine
	go h.cleanupFingerprints()

	// Load existing node names from storage for loop detection
	h.loadNodeNamesFromStorage()

	h.Log.Info("bridge enabled",
		"mappings", len(h.config.Bridge.ChannelMappings),
		"mesh_id", h.config.Bridge.MeshID,
		"topic_prefix", h.mcTopicPrefix,
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
				return crypto.DefaultKey
			}
			key, err := crypto.ParseKey(ch.Key)
			if err != nil {
				return nil
			}
			return key
		}
	}
	// Default to LongFast with default key
	if channelName == "LongFast" || channelName == "LongSlow" || channelName == "VLongSlow" {
		return crypto.DefaultKey
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
	if matches := h.mcTopicRegex.FindStringSubmatch(pk.TopicName); len(matches) > 0 {
		h.handleMeshCoreMessage(pk, matches[1])
		return pk, nil
	}

	return pk, nil
}

// handleMeshtasticMessage processes a Meshtastic message — bridges text to MeshCore
// and responds to NODEINFO requests targeting virtual nodes.
func (h *BridgeHook) handleMeshtasticMessage(pk packets.Packet, topicRoot, channel, gateway string) {
	// Look up mapping
	mappingKey := topicRoot + "/" + channel
	idx, ok := h.mtMappings[mappingKey]
	if !ok {
		return // No mapping for this channel
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

	// Loop prevention: check if sender is a virtual node (bridged from MeshCore)
	if h.config.Storage != nil {
		isVirtual, err := h.config.Storage.VirtualNodes.IsVirtualNode(packet.From)
		if err != nil {
			h.Log.Warn("failed to check virtual node", "error", err)
		} else if isVirtual {
			h.Log.Debug("ignoring packet from virtual node (loop prevention)",
				"from", fmt.Sprintf("!%08x", packet.From))
			return
		}
	}

	// Decrypt the packet
	data, err := crypto.TryDecode(packet, idx.meshtasticKey)
	if err != nil {
		h.Log.Debug("failed to decrypt Meshtastic packet", "error", err)
		return
	}

	switch data.Portnum {
	case pb.PortNum_TEXT_MESSAGE_APP:
		h.handleMeshtasticTextMessage(idx, packet, data, channel)

	case pb.PortNum_NODEINFO_APP:
		h.handleMeshtasticNodeInfoRequest(idx, packet, data)
	}
}

// handleMeshtasticTextMessage bridges a text message from Meshtastic to MeshCore.
func (h *BridgeHook) handleMeshtasticTextMessage(idx *channelMappingIndex, packet *pb.MeshPacket, data *pb.Data, channel string) {
	// Only bridge broadcast messages — DMs can't be represented in MeshCore group chat
	if packet.To != 0xFFFFFFFF {
		return
	}

	// Check direction — only bridge if mt_to_mc is allowed
	if idx.mapping.Direction != "both" && idx.mapping.Direction != "mt_to_mc" {
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

// handleMeshtasticNodeInfoRequest responds to NODEINFO requests targeting virtual nodes.
func (h *BridgeHook) handleMeshtasticNodeInfoRequest(idx *channelMappingIndex, packet *pb.MeshPacket, data *pb.Data) {
	// Only respond to explicit requests (WantResponse set)
	if !data.WantResponse {
		return
	}

	// Only respond if the target is a virtual node
	if h.config.Storage == nil {
		return
	}

	virtualNode, err := h.config.Storage.VirtualNodes.GetByNodeID(packet.To)
	if err != nil {
		h.Log.Warn("failed to look up virtual node for NODEINFO request", "error", err)
		return
	}
	if virtualNode == nil {
		return // Not our virtual node
	}

	displayName := virtualNode.DisplayName
	if displayName == "" {
		displayName = fmt.Sprintf("!%08x", packet.To)
	}

	h.Log.Debug("responding to NODEINFO request for virtual node",
		"virtual_node", fmt.Sprintf("!%08x", packet.To),
		"requester", fmt.Sprintf("!%08x", packet.From),
		"name", displayName)

	h.respondToNodeInfoRequest(idx, packet.Id, packet.From, packet.To, displayName)
}

// handleMeshCoreMessage processes a MeshCore message and bridges to Meshtastic.
func (h *BridgeHook) handleMeshCoreMessage(pk packets.Packet, meshID string) {
	// Decode base64 payload (raw MeshCore packet, not RS232 framed)
	rawData, err := base64.StdEncoding.DecodeString(string(pk.Payload))
	if err != nil {
		h.Log.Debug("failed to decode base64 payload", "error", err)
		return
	}

	// Parse MeshCore packet directly from decoded bytes
	var mcPacket codec.Packet
	if err := mcPacket.ReadFrom(rawData); err != nil {
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

		// Extract sender name from "Name: message" format
		senderName, msgContent, hasSender := ParseSenderFromMessage(message)

		// Try to get or create a virtual node for identity-preserving bridging
		var virtualNodeID uint32
		var displayName string
		var isNewVirtualNode bool
		if hasSender && senderName != "" {
			virtualNodeID, displayName, isNewVirtualNode = h.getOrCreateVirtualNode(senderName)
		}

		// Format message for Meshtastic
		var formattedMsg string
		if virtualNodeID != 0 {
			// We have a virtual node - the From field will identify the sender,
			// so we only need the message content (optionally with prefix)
			if h.config.Bridge.MeshCorePrefix != "" {
				formattedMsg = h.config.Bridge.MeshCorePrefix + msgContent
			} else {
				formattedMsg = msgContent
			}
			h.Log.Debug("bridging with virtual node identity",
				"sender", displayName,
				"virtual_node_id", fmt.Sprintf("!%08x", virtualNodeID))
		} else {
			// No virtual node - include sender name in message text
			formattedMsg, _ = FormatMeshCoreToMeshtastic(message, h.config.Bridge.MeshCorePrefix, h.config.Bridge.ParseSenderName)
		}
		formattedMsg = TruncateMessage(formattedMsg, maxBridgeMessageLen)

		// Send to Meshtastic
		h.sendToMeshtastic(idx, formattedMsg, virtualNodeID)

		// Broadcast NODEINFO for new virtual nodes so clients learn about them
		if isNewVirtualNode && virtualNodeID != 0 {
			h.broadcastVirtualNodeInfo(idx, virtualNodeID, displayName)
		}

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

	// Encode packet and base64 encode (raw packet, no RS232 framing)
	packetBytes := mcPacket.WriteTo()
	b64Payload := base64.StdEncoding.EncodeToString(packetBytes)

	// Publish to MeshCore topic using this bridge's mesh ID
	topic := h.mcTopicPrefix + "/" + h.config.Bridge.MeshID

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
// If virtualNodeID is non-zero, uses it as the From field (for identity-preserving bridging).
// Otherwise uses the bridge's own node ID.
func (h *BridgeHook) sendToMeshtastic(idx *channelMappingIndex, message string, virtualNodeID uint32) {
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
	if virtualNodeID != 0 {
		fromNode = virtualNodeID
	}

	encrypted, err := crypto.XOR(rawData, idx.meshtasticKey, packetID, fromNode)
	if err != nil {
		h.Log.Error("failed to encrypt Meshtastic packet", "error", err)
		return
	}

	// Build MeshPacket
	hopStart, hopLimit := h.getHopValues()
	msgTime := uint32(time.Now().Unix())
	pkt := pb.MeshPacket{
		Id:       packetID,
		To:       uint32(0xFFFFFFFF), // Broadcast
		From:     fromNode,
		HopLimit: hopLimit,
		HopStart: hopStart,
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

// getHopValues returns the HopStart and HopLimit for bridged packets.
// The bridge consumes one hop, so HopLimit = configured - 1.
func (h *BridgeHook) getHopValues() (hopStart, hopLimit uint32) {
	configured := h.config.Bridge.HopLimit
	if configured <= 0 {
		configured = 3
	}
	if configured > 7 {
		configured = 7
	}
	hopStart = uint32(configured)
	hopLimit = hopStart - 1
	return
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

// MCPubKeyToNodeID converts a MeshCore ed25519 public key to a Meshtastic-style NodeID
// using CRC32 for a deterministic 32-bit mapping.
func MCPubKeyToNodeID(pubkey []byte) uint32 {
	return crc32.ChecksumIEEE(pubkey)
}

// mcNodeTypeToRole maps a MeshCore node type to the appropriate Meshtastic device role.
func mcNodeTypeToRole(nodeType int16) pb.Config_DeviceConfig_Role {
	switch uint8(nodeType) {
	case codec.NodeTypeChat:
		return pb.Config_DeviceConfig_CLIENT_MUTE
	case codec.NodeTypeRepeater:
		return pb.Config_DeviceConfig_CLIENT_BASE
	case codec.NodeTypeRoom:
		return pb.Config_DeviceConfig_CLIENT_MUTE
	case codec.NodeTypeSensor:
		return pb.Config_DeviceConfig_SENSOR
	default:
		return pb.Config_DeviceConfig_CLIENT
	}
}

// lookupVirtualNodeMCInfo retrieves the MeshCore node info for a virtual node by
// decoding its ExternalID (hex pubkey) and looking up the MeshCore node record.
func (h *BridgeHook) lookupVirtualNodeMCInfo(virtualNodeID uint32) *models.MeshCoreNodeInfo {
	if h.config.Storage == nil {
		return nil
	}

	virtualNode, err := h.config.Storage.VirtualNodes.GetByNodeID(virtualNodeID)
	if err != nil || virtualNode == nil {
		return nil
	}

	pubKey, err := hex.DecodeString(virtualNode.ExternalID)
	if err != nil || len(pubKey) < 32 {
		return nil
	}

	mcNode, err := h.config.Storage.MeshCoreNodes.GetNode(pubKey)
	if err != nil || mcNode == nil {
		return nil
	}

	return mcNode
}

// ed25519PubKeyToX25519 converts an Ed25519 public key to an X25519 public key
// by converting from Edwards to Montgomery form.
func ed25519PubKeyToX25519(edPubKey []byte) ([]byte, error) {
	point, err := new(edwards25519.Point).SetBytes(edPubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid Ed25519 public key: %w", err)
	}
	return point.BytesMontgomery(), nil
}

// broadcastVirtualNodeInfo broadcasts NODEINFO for a virtual node so Meshtastic clients
// can learn about it. This is called when a virtual node first sends a message.
func (h *BridgeHook) broadcastVirtualNodeInfo(idx *channelMappingIndex, virtualNodeID uint32, displayName string) {
	// Build short name (up to 4 chars)
	shortName := displayName
	if len(shortName) > 4 {
		shortName = shortName[:4]
	}

	// Build long name with source prefix
	longName := "MC:" + displayName
	if len(longName) > 39 { // Meshtastic limit
		longName = longName[:39]
	}

	// Look up MeshCore node info for role and public key
	var nodeType int16
	var x25519Key []byte
	if mcNode := h.lookupVirtualNodeMCInfo(virtualNodeID); mcNode != nil {
		nodeType = mcNode.NodeType
		if k, err := ed25519PubKeyToX25519(mcNode.PubKey); err == nil {
			x25519Key = k
		}
	}
	role := mcNodeTypeToRole(nodeType)
	unmessagable := true

	// Build User (NODEINFO) payload
	user := &pb.User{
		Id:              fmt.Sprintf("!%08x", virtualNodeID),
		LongName:        longName,
		ShortName:       shortName,
		HwModel:         pb.HardwareModel_PRIVATE_HW, // Signals this is a bridged/virtual node
		Role:            role,
		IsUnmessagable:  &unmessagable,
		PublicKey:        x25519Key,
	}

	rawUser, err := proto.Marshal(user)
	if err != nil {
		h.Log.Error("failed to marshal NODEINFO for virtual node", "error", err)
		return
	}

	// Build Meshtastic Data payload
	bitfield := uint32(BITFIELD_OkToMQTT)
	data := pb.Data{
		Portnum:  pb.PortNum_NODEINFO_APP,
		Payload:  rawUser,
		Bitfield: &bitfield,
	}

	rawData, err := proto.Marshal(&data)
	if err != nil {
		h.Log.Error("failed to marshal Data for virtual node NODEINFO", "error", err)
		return
	}

	// Encrypt
	packetID := h.generatePacketID()
	encrypted, err := crypto.XOR(rawData, idx.meshtasticKey, packetID, virtualNodeID)
	if err != nil {
		h.Log.Error("failed to encrypt virtual node NODEINFO", "error", err)
		return
	}

	// Build MeshPacket - broadcast to all
	hopStart, hopLimit := h.getHopValues()
	msgTime := uint32(time.Now().Unix())
	pkt := pb.MeshPacket{
		Id:       packetID,
		To:       uint32(0xFFFFFFFF), // Broadcast
		From:     virtualNodeID,
		HopLimit: hopLimit,
		HopStart: hopStart,
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
		h.Log.Error("failed to marshal ServiceEnvelope for virtual node NODEINFO", "error", err)
		return
	}

	// Publish to Meshtastic topic using the server's gateway ID (for ACL)
	topic := idx.mapping.MeshtasticTopicRoot + "/2/e/" + idx.mapping.MeshtasticChannel + "/" + h.config.MeshSettings.SelfNode.NodeID.String()

	go func(t string, payload []byte) {
		// Small delay before NODEINFO to allow text message to be processed first
		time.Sleep(100 * time.Millisecond)

		err := h.config.Server.Publish(t, payload, false, 0)
		if err != nil {
			h.Log.Error("failed to publish virtual node NODEINFO", "error", err, "topic", t)
		} else {
			h.Log.Debug("broadcast NODEINFO for virtual node",
				"node_id", fmt.Sprintf("!%08x", virtualNodeID),
				"name", displayName)
		}
	}(topic, rawEnv)
}

// respondToNodeInfoRequest sends a unicast NODEINFO response for a virtual node.
func (h *BridgeHook) respondToNodeInfoRequest(idx *channelMappingIndex, requestPacketID uint32, requesterNodeID uint32, virtualNodeID uint32, displayName string) {
	// Build short name (up to 4 chars)
	shortName := displayName
	if len(shortName) > 4 {
		shortName = shortName[:4]
	}

	// Build long name with source prefix
	longName := "MC:" + displayName
	if len(longName) > 39 { // Meshtastic limit
		longName = longName[:39]
	}

	// Look up MeshCore node info for role and public key
	var nodeType int16
	var x25519Key []byte
	if mcNode := h.lookupVirtualNodeMCInfo(virtualNodeID); mcNode != nil {
		nodeType = mcNode.NodeType
		if k, err := ed25519PubKeyToX25519(mcNode.PubKey); err == nil {
			x25519Key = k
		}
	}
	role := mcNodeTypeToRole(nodeType)
	unmessagable := true

	// Build User (NODEINFO) payload
	user := &pb.User{
		Id:              fmt.Sprintf("!%08x", virtualNodeID),
		LongName:        longName,
		ShortName:       shortName,
		HwModel:         pb.HardwareModel_PRIVATE_HW,
		Role:            role,
		IsUnmessagable:  &unmessagable,
		PublicKey:        x25519Key,
	}

	rawUser, err := proto.Marshal(user)
	if err != nil {
		h.Log.Error("failed to marshal NODEINFO response", "error", err)
		return
	}

	// Build Data with RequestId to mark this as a response
	bitfield := uint32(BITFIELD_OkToMQTT)
	data := pb.Data{
		Portnum:   pb.PortNum_NODEINFO_APP,
		Payload:   rawUser,
		Bitfield:  &bitfield,
		RequestId: requestPacketID,
	}

	rawData, err := proto.Marshal(&data)
	if err != nil {
		h.Log.Error("failed to marshal Data for NODEINFO response", "error", err)
		return
	}

	// Encrypt
	packetID := h.generatePacketID()
	encrypted, err := crypto.XOR(rawData, idx.meshtasticKey, packetID, virtualNodeID)
	if err != nil {
		h.Log.Error("failed to encrypt NODEINFO response", "error", err)
		return
	}

	// Build MeshPacket - unicast to requester
	hopStart, hopLimit := h.getHopValues()
	msgTime := uint32(time.Now().Unix())
	pkt := pb.MeshPacket{
		Id:       packetID,
		To:       requesterNodeID,
		From:     virtualNodeID,
		HopLimit: hopLimit,
		HopStart: hopStart,
		ViaMqtt:  true,
		RxTime:   msgTime,
		Channel:  idx.meshtasticHash,
		Priority: pb.MeshPacket_DEFAULT,
		Delayed:  pb.MeshPacket_NO_DELAY,
		PayloadVariant: &pb.MeshPacket_Encrypted{
			Encrypted: encrypted,
		},
	}

	// Build ServiceEnvelope — use the server's gateway ID so ACL allows delivery
	env := pb.ServiceEnvelope{
		ChannelId: idx.mapping.MeshtasticChannel,
		GatewayId: h.config.MeshSettings.SelfNode.NodeID.String(),
		Packet:    &pkt,
	}

	rawEnv, err := proto.Marshal(&env)
	if err != nil {
		h.Log.Error("failed to marshal ServiceEnvelope for NODEINFO response", "error", err)
		return
	}

	topic := idx.mapping.MeshtasticTopicRoot + "/2/e/" + idx.mapping.MeshtasticChannel + "/" + h.config.MeshSettings.SelfNode.NodeID.String()

	go func(t string, payload []byte) {
		time.Sleep(200 * time.Millisecond)

		err := h.config.Server.Publish(t, payload, false, 0)
		if err != nil {
			h.Log.Error("failed to publish NODEINFO response", "error", err, "topic", t)
		} else {
			h.Log.Debug("sent NODEINFO response for virtual node",
				"node_id", fmt.Sprintf("!%08x", virtualNodeID),
				"requester", fmt.Sprintf("!%08x", requesterNodeID),
				"name", displayName)
		}
	}(topic, rawEnv)
}

// getOrCreateVirtualNode looks up or creates a virtual node for a MeshCore identity.
// Returns the virtual node's Meshtastic NodeID, display name, and whether this is a newly created node.
func (h *BridgeHook) getOrCreateVirtualNode(senderName string) (uint32, string, bool) {
	if h.config.Storage == nil {
		return 0, senderName, false
	}

	// Try to find the MeshCore node by name
	mcNodes, err := h.config.Storage.MeshCoreNodes.GetAllNodes()
	if err != nil {
		h.Log.Warn("failed to load MeshCore nodes for virtual node lookup", "error", err)
		return 0, senderName, false
	}

	var matchedNode *models.MeshCoreNodeInfo
	for _, node := range mcNodes {
		if node.Name == senderName {
			matchedNode = node
			break
		}
	}

	if matchedNode == nil || len(matchedNode.PubKey) < 32 {
		// No matching MeshCore node found - can't create virtual node
		h.Log.Debug("no matching MeshCore node found for sender", "sender", senderName)
		return 0, senderName, false
	}

	// Compute virtual NodeID from pubkey
	virtualNodeID := MCPubKeyToNodeID(matchedNode.PubKey)

	// Check if we already have this virtual node
	existingNode, err := h.config.Storage.VirtualNodes.GetByNodeID(virtualNodeID)
	if err != nil {
		h.Log.Warn("failed to lookup virtual node", "error", err)
		return virtualNodeID, senderName, false
	}

	now := time.Now()
	if existingNode != nil {
		// Update display name if sender name has changed
		if senderName != "" && existingNode.DisplayName != senderName {
			existingNode.DisplayName = senderName
			existingNode.LastSeen = now
			if err := h.config.Storage.VirtualNodes.Save(existingNode); err != nil {
				h.Log.Warn("failed to update virtual node display name", "error", err)
			} else {
				h.Log.Info("updated virtual node display name from message",
					"node_id", fmt.Sprintf("!%08x", virtualNodeID),
					"new_name", senderName)
			}
		} else {
			// Just update last seen
			if err := h.config.Storage.VirtualNodes.UpdateLastSeen(virtualNodeID); err != nil {
				h.Log.Warn("failed to update virtual node last seen", "error", err)
			}
		}
		displayName := existingNode.DisplayName
		if displayName == "" {
			displayName = senderName
		}
		return virtualNodeID, displayName, false
	}

	// Create new virtual node
	virtualNode := &models.VirtualNode{
		NodeID:      virtualNodeID,
		Source:      models.VirtualNodeSourceMeshCore,
		ExternalID:  hex.EncodeToString(matchedNode.PubKey),
		DisplayName: senderName,
		FirstSeen:   now,
		LastSeen:    now,
	}

	if err := h.config.Storage.VirtualNodes.Save(virtualNode); err != nil {
		h.Log.Warn("failed to save virtual node", "error", err)
		return virtualNodeID, senderName, false
	}

	h.Log.Info("created virtual node for MeshCore user",
		"node_id", fmt.Sprintf("!%08x", virtualNodeID),
		"name", senderName,
		"pubkey_prefix", hex.EncodeToString(matchedNode.PubKey[:8]))

	return virtualNodeID, senderName, true
}
