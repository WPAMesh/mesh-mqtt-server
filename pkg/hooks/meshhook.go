package hooks

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/hooks/auth"
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/kabili207/mesh-mqtt-server/pkg/config"
	"github.com/kabili207/mesh-mqtt-server/pkg/meshtastic"
	pb "github.com/kabili207/mesh-mqtt-server/pkg/meshtastic/generated"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
	"github.com/kabili207/mesh-mqtt-server/pkg/store"
	"google.golang.org/protobuf/proto"
)

const (
	meshDevicePattern   = `^(?:Meshtastic(Android|Apple)MqttProxy-)?(![0-9a-f]{8})$`
	unknownProxyPattern = `^Meshtastic(Android|Apple)MqttProxy-(.+)$`
	channelPattern      = `^(msh(?:\/[^\/\n]+?)*)\/2\/e\/(\w+)\/(![a-f0-9]{8})$`
	gatewayTopicPattern = `^(msh(?:\/[^\/\n]+?)*)(\/Gateway)\/2\/e\/([^/]+)\/(![a-f0-9]{8})$`

	// Regex for exact gateway publish topic
	gatewayPublishPattern = `^(msh(?:\/[^\/\n]+?)*)(\/Gateway)\/2\/e\/[^/]+\/(![a-f0-9]{8})$`
	gatewaySubPattern     = `^(msh(?:\/[^\/\n]+?)*)(\/Gateway)\/2\/e\/.*`

	gatewayReplacement = `$1/2/e/$3/$4`

	meshFilter auth.RString = `msh/#`
	sysFilter  auth.RString = `$SYS/#`
)

var (
	meshDeviceRegex     = regexp.MustCompile(meshDevicePattern)
	unknownProxyRegex   = regexp.MustCompile(unknownProxyPattern)
	channelRegex        = regexp.MustCompile(channelPattern)
	gatewayTopicRegex   = regexp.MustCompile(gatewayTopicPattern)
	gatewayPublishRegex = regexp.MustCompile(gatewayPublishPattern)
	gatewaySubRegex     = regexp.MustCompile(gatewaySubPattern)

	// Allowed suffixes for concrete publish topics.
	publishSuffixes = [][]string{
		{"Gateway", "2", "e", "+", "+"},
		{"Gateway", "2", "map", ""},
	}

	// Allowed suffixes for subscriptions (includes publishSuffixes plus # variants).
	subscribeSuffixes = [][]string{
		{"Gateway", "2", "e", "+", "+"},
		{"Gateway", "2", "map", ""},
		{"Gateway", "#"},
		{"Gateway", "2", "#"},
	}
)

// ClientChangeNotifier is an interface for notifying when clients change
type ClientChangeNotifier interface {
	Notify()
}

// Options contains configuration settings for the hook.
type MeshtasticHookOptions struct {
	Server         *mqtt.Server
	Storage        *store.Stores
	MeshSettings   config.MeshSettings
	ClientNotifier ClientChangeNotifier
}

var _ models.MeshMqttServer = (*MeshtasticHook)(nil)

const (
	// VerificationCheckInterval is how often to check for expiring gateway verifications
	VerificationCheckInterval = 1 * time.Hour
)

type MeshtasticHook struct {
	mqtt.HookBase
	config          *MeshtasticHookOptions
	knownClients    map[string]*models.ClientDetails
	clientLock      sync.RWMutex
	currentPacketId uint32
	stopChan        chan struct{}
}

func (h *MeshtasticHook) ID() string {
	return "mesht-hook"
}

func (h *MeshtasticHook) Provides(b byte) bool {
	return bytes.Contains([]byte{
		mqtt.OnConnectAuthenticate,
		mqtt.OnACLCheck,
		mqtt.OnConnect,
		mqtt.OnDisconnect,
		mqtt.OnSubscribe,
		mqtt.OnSubscribed,
		mqtt.OnUnsubscribed,
		mqtt.OnPublished,
		mqtt.OnPublish,
	}, []byte{b})
}

func (h *MeshtasticHook) Init(config any) error {
	h.Log.Info("initialised")
	if _, ok := config.(*MeshtasticHookOptions); !ok && config != nil {
		return mqtt.ErrInvalidConfigType
	}

	h.config = config.(*MeshtasticHookOptions)
	if h.config.Server == nil {
		return mqtt.ErrInvalidConfigType
	}

	if h.config.Storage == nil {
		return mqtt.ErrInvalidConfigType
	}

	h.knownClients = make(map[string]*models.ClientDetails)
	h.stopChan = make(chan struct{})

	// Start periodic verification checker
	go h.runPeriodicVerificationChecker()

	return nil
}

// Stop gracefully shuts down the hook's background goroutines
func (h *MeshtasticHook) Stop() error {
	h.Log.Info("stopping mesht-hook")
	if h.stopChan != nil {
		close(h.stopChan)
	}
	return nil
}

// runPeriodicVerificationChecker periodically checks all connected gateway clients
// for expiring verifications and triggers re-verification as needed
func (h *MeshtasticHook) runPeriodicVerificationChecker() {
	ticker := time.NewTicker(VerificationCheckInterval)
	defer ticker.Stop()

	h.Log.Info("started periodic verification checker", "interval", VerificationCheckInterval)

	for {
		select {
		case <-h.stopChan:
			h.Log.Info("stopping periodic verification checker")
			return
		case <-ticker.C:
			h.checkExpiringVerifications()
		}
	}
}

// checkExpiringVerifications iterates through all connected clients and triggers
// re-verification for any gateway clients whose verification is expiring soon
func (h *MeshtasticHook) checkExpiringVerifications() {
	h.clientLock.RLock()
	clientIDs := make([]string, 0, len(h.knownClients))
	for clientID := range h.knownClients {
		clientIDs = append(clientIDs, clientID)
	}
	h.clientLock.RUnlock()

	reverifiedCount := 0
	for _, clientID := range clientIDs {
		h.clientLock.RLock()
		cd, ok := h.knownClients[clientID]
		h.clientLock.RUnlock()

		if !ok {
			continue
		}

		cd.RLock()
		shouldVerify := cd.ShouldStartVerification(false)
		cd.RUnlock()

		if shouldVerify {
			h.Log.Info("triggering re-verification for expiring gateway",
				"client", clientID)
			h.TryVerifyNode(clientID, false)
			reverifiedCount++
		}
	}

	if reverifiedCount > 0 {
		h.Log.Info("periodic verification check complete",
			"clients_checked", len(clientIDs),
			"reverification_triggered", reverifiedCount)
	}
}

func (h *MeshtasticHook) GetAllClients() []*models.ClientDetails {
	h.clientLock.RLock()
	userClients := make([]*models.ClientDetails, 0, len(h.knownClients))
	for _, c := range h.knownClients {
		userClients = append(userClients, c)
	}
	h.clientLock.RUnlock()

	return userClients
}

func (h *MeshtasticHook) GetUserClients(mqttUser string) []*models.ClientDetails {
	h.clientLock.RLock()
	userClients := make([]*models.ClientDetails, 0, len(h.knownClients))
	for _, c := range h.knownClients {
		if c.MqttUserName == mqttUser {
			userClients = append(userClients, c)
		}
	}
	h.clientLock.RUnlock()

	return userClients
}

// notifyClientChange triggers a notification that clients have changed
func (h *MeshtasticHook) notifyClientChange() {
	if h.config.ClientNotifier != nil {
		h.config.ClientNotifier.Notify()
	}
}

// OnConnectAuthenticate returns true if the connecting client is allowed to connect
// and stores details about the client for later
func (h *MeshtasticHook) OnConnectAuthenticate(cl *mqtt.Client, pk packets.Packet) bool {
	user := string(pk.Connect.Username)
	pass := pk.Connect.Password
	clientID := cl.ID
	validatedUser := h.validateUser(user, string(pass))
	if validatedUser != nil {

		nodeDetails, proxyType := (*models.NodeInfo)(nil), ""
		if meshDeviceRegex.MatchString(cl.ID) {
			matches := meshDeviceRegex.FindStringSubmatch(cl.ID)
			proxyType = matches[1]
			nid, err := meshtastic.ParseNodeID(matches[2])
			if err == nil {
				nodeDetails, err = h.config.Storage.NodeDB.GetNode(uint32(nid), validatedUser.ID)
				if err != nil {
					h.Log.Error("error loading node info", "node_id", nid, "user_id", validatedUser.ID, "error", err)
				} else if nodeDetails == nil {
					nodeDetails = &models.NodeInfo{NodeID: nid, UserID: validatedUser.ID}
				}
			}
		} else if unknownProxyRegex.MatchString(cl.ID) {
			matches := unknownProxyRegex.FindStringSubmatch(cl.ID)
			proxyType = matches[1]
			//nodeID = matches[2]
		}

		h.clientLock.Lock()
		cd := &models.ClientDetails{
			MqttUserName:   user,
			ClientID:       clientID,
			UserID:         validatedUser.ID,
			NodeDetails:    nodeDetails,
			ProxyType:      proxyType,
			Address:        cl.Net.Remote,
			ValidGWChecker: h.makeGatewayValidator(validatedUser.ID),
		}
		h.knownClients[clientID] = cd
		h.clientLock.Unlock()
		if nodeDetails != nil {
			h.Log.Info("client authenticated", "username", user, "client", clientID, "node", nodeDetails.GetDisplayName(), "proxy", proxyType)
			go h.TryVerifyNode(cl.ID, false)
		} else {
			h.Log.Info("client authenticated", "username", user, "client", clientID, "proxy", proxyType)
		}

		// Notify subscribers about the new client
		go h.notifyClientChange()
	}
	if validatedUser == nil {
		h.Log.Warn("authentication failed", "username", user, "remote_addr", cl.Net.Remote)
	}
	return validatedUser != nil
}

func (h *MeshtasticHook) makeGatewayValidator(userID int) func() bool {
	return func() bool {
		ok, err := h.config.Storage.Users.IsGatewayAllowed(userID)
		if err != nil {
			h.Log.Warn("error checking for gateway permission", "user_id", userID)
		}
		return ok
	}
}

// OnACLCheck returns true if the connecting client has matching read or write access to subscribe
// or publish to a given topic.
func (h *MeshtasticHook) OnACLCheck(cl *mqtt.Client, topic string, write bool) bool {

	h.clientLock.RLock()
	cd, ok := h.knownClients[cl.ID]
	if !ok {
		h.clientLock.RUnlock()
		h.Log.Warn("unknown client in ACL check",
			"client", cl.ID,
			"username", string(cl.Properties.Username),
			"topic", topic)
		return false
	}

	// Check superuser status (database layer has its own cache)
	isSU, err := h.config.Storage.Users.IsSuperuser(cd.UserID)
	if err != nil {
		h.Log.Warn("error checking superuser status", "user_id", cd.UserID, "error", err)
		isSU = false
	}

	// Keep the lock for the remaining checks
	defer h.clientLock.RUnlock()

	if sysFilter.FilterMatches(topic) {
		if !isSU {
			h.Log.Warn("ACL denied: non-superuser accessing $SYS topic",
				"client", cl.ID,
				"user", cd.MqttUserName,
				"topic", topic)
		}
		return isSU
	}

	if !cd.IsMeshDevice() {
		// Non-mesh devices can write to mesh topics, but doing so marks them as
		// a publisher and blocks all future reads. This prevents unauthorized
		// bridges from acting as gateways.
		if write {
			if !cd.HasPublished {
				cd.HasPublished = true
				h.Log.Info("non-mesh device published to mesh topic, blocking future reads",
					"client", cl.ID,
					"user", cd.MqttUserName,
					"topic", topic)
			}
			return true
		}

		// Block all mesh topic reads for non-mesh devices that have published
		if cd.HasPublished {
			h.Log.Debug("blocking read for non-mesh publisher",
				"client", cl.ID,
				"topic", topic)
			return false
		}

		// For reads on gateway topics, block if the publisher is an unvalidated gateway
		// This prevents mapping software (including superusers) from receiving duplicate messages
		if h.shouldBlockUnvalidatedGatewayMessageUnsafe(topic) {
			h.Log.Debug("blocking non-mesh device from unvalidated gateway message",
				"reader", cl.ID, "is_superuser", isSU, "topic", topic)
			return false
		}

		// Allow reads for all other topics (mapping software that doesn't publish)
		return true
	}

	if topic == "will" || topic == "/will" {
		return true
	}

	isMeshTopic := meshFilter.FilterMatches(topic)
	// Gateway topics also match this pattern
	if !isMeshTopic {
		return false
	}

	// Any clients left should be a node, which are always allowed to write.
	// Gateway validation is done elsewhere, so it's safe to allow anyone to read.
	isAllowed := h.checkGatewayACL(cd, topic, write)
	result := write || isAllowed

	if !result {
		h.Log.Debug("ACL denied: gateway check failed",
			"client", cl.ID,
			"user", cd.MqttUserName,
			"topic", topic,
			"write", write,
			"is_valid_gateway", cd.IsValidGateway())
	}

	return result
}

// getClientByNodeIDUnsafe looks up a client by node ID without locking
// Caller MUST hold clientLock (RLock or Lock)
func (h *MeshtasticHook) getClientByNodeIDUnsafe(nodeID meshtastic.NodeID) *models.ClientDetails {
	for _, client := range h.knownClients {
		if client.NodeDetails != nil && client.NodeDetails.NodeID == nodeID {
			return client
		}
	}
	return nil
}

func (h *MeshtasticHook) isPublisherValidGatewayUnsafe(pubID meshtastic.NodeID) bool {
	client := h.getClientByNodeIDUnsafe(pubID)
	return client != nil && client.IsValidGateway()
}

func (h *MeshtasticHook) shouldBlockUnvalidatedGatewayMessageUnsafe(topic string) bool {
	// Check if this is a concrete gateway topic (not a subscription pattern)
	if !gatewayPublishRegex.MatchString(topic) {
		return false
	}

	matches := gatewayPublishRegex.FindStringSubmatch(topic)
	if len(matches) == 0 {
		return false
	}

	pubID, err := meshtastic.ParseNodeID(matches[3])
	if err != nil {
		return false
	}

	// Check if the publisher is an unvalidated gateway
	publisherClient := h.getClientByNodeIDUnsafe(pubID)
	if publisherClient != nil && publisherClient.IsMeshDevice() && !publisherClient.IsValidGateway() {
		return true
	}

	return false
}

func (h *MeshtasticHook) checkGatewayACL(cd *models.ClientDetails, topic string, write bool) bool {
	if !strings.HasPrefix(topic, "msh/") {
		return false
	}
	if write {
		return true
	}

	// For reads, check if this is a gateway topic
	if gatewaySubRegex.MatchString(topic) {
		// Gateway topic - check if this is a concrete publish topic that needs strict validation
		matches := gatewayPublishRegex.FindStringSubmatch(topic)
		if len(matches) > 0 {
			// Concrete gateway topic - only allow if publisher is self OR reader is valid gateway
			if pubID, err := meshtastic.ParseNodeID(matches[3]); err == nil {
				// Always allow nodes to receive their own messages (required for firmware ACK logic)
				if cd.NodeDetails != nil && cd.NodeDetails.NodeID == pubID {
					h.Log.Debug("Allowing self-message", "client", cd.ClientID, "node_id", cd.NodeDetails.NodeID, "publisher", pubID, "topic", topic)
					return true
				}

				// Always allow messages from the server (including verification packets)
				if pubID == h.config.MeshSettings.SelfNode.NodeID {
					h.Log.Debug("Allowing server message", "client", cd.ClientID, "publisher", pubID, "topic", topic)
					return true
				}

				// For validated gateway readers, also allow messages from other validated gateways
				if cd.IsValidGateway() {
					isValidGatewayPub := h.isPublisherValidGatewayUnsafe(pubID)
					if isValidGatewayPub {
						return true
					}
					h.Log.Debug("Blocking unvalidated gateway message to validated gateway",
						"reader", cd.ClientID, "publisher", pubID, "topic", topic)
					return false
				}
				// Non-gateway readers don't get gateway topic messages from other nodes
				h.Log.Debug("Not forwarding packet to invalid gateway", "client", cd.ClientID, "topic", topic, "publisher", pubID, "has_node_details", cd.NodeDetails != nil)
				return false
			}
		}
		// Subscription patterns or topics that couldn't be parsed are allowed
		return true
	}

	// Non-gateway mesh topics are write-only (for mapping)
	// EXCEPT: allow nodes to receive their own messages even if redirected to non-gateway topics
	// This is needed for firmware ACK logic when gateways aren't validated yet
	if cd.NodeDetails != nil {
		matches := channelRegex.FindStringSubmatch(topic)
		if len(matches) > 0 {
			if pubID, err := meshtastic.ParseNodeID(matches[3]); err == nil {
				if cd.NodeDetails.NodeID == pubID {
					h.Log.Debug("Allowing self-message on non-gateway topic", "client", cd.ClientID, "node_id", cd.NodeDetails.NodeID, "publisher", pubID, "topic", topic)
					return true
				}
			}
		}
	}

	// Allow subscription patterns (to keep clients happy) but deny concrete topic delivery
	hasWildcard := strings.Contains(topic, "+") || strings.Contains(topic, "#")
	return hasWildcard
}

// subscribeCallback handles messages for subscribed topics
func (h *MeshtasticHook) subscribeCallback(cl *mqtt.Client, sub packets.Subscription, pk packets.Packet) {
	h.Log.Debug("hook subscribed message", "client", cl.ID, "topic", pk.TopicName)
}

func (h *MeshtasticHook) OnConnect(cl *mqtt.Client, pk packets.Packet) error {
	h.Log.Debug("client connected", "client", cl.ID, "keepalive", pk.Connect.Keepalive, "clean_start", pk.Connect.Clean)

	// Override very short keepalive intervals (< 60 seconds) to prevent frequent reconnections
	// Meshtastic firmware uses 15 seconds which is too aggressive for mesh network conditions
	if pk.Connect.Keepalive > 0 && pk.Connect.Keepalive < 60 {
		originalKeepalive := pk.Connect.Keepalive
		cl.State.Keepalive = 60 // Set to 60 seconds minimum
		cl.State.ServerKeepalive = true
		h.Log.Info("overriding short keepalive", "client", cl.ID, "original", originalKeepalive, "override", 60)
	}

	return nil
}

func (h *MeshtasticHook) TryVerifyNode(clientID string, force bool) {
	h.clientLock.Lock()
	cd, ok := h.knownClients[clientID]
	h.clientLock.Unlock()

	if !ok {
		return
	}

	cd.RLock()
	shouldReq := cd.ShouldStartVerification(force)
	shouldTryNextChannel := cd.IsUsingGatewayTopic() && cd.ShouldTryNextChannel()
	currentChannel := cd.VerifyChannel
	cd.RUnlock()

	if shouldReq {
		// Start a new verification request
		cd.Lock()
		defer cd.Unlock()
		h.RequestNodeInfo(cd)
		return
	}

	if shouldTryNextChannel {
		// Current channel timed out, try the next one
		nextChannel := h.getNextVerificationChannel(currentChannel)
		if nextChannel != "" {
			cd.Lock()
			defer cd.Unlock()
			h.Log.Info("channel verification timeout, trying next channel",
				"client", clientID,
				"previous_channel", currentChannel,
				"next_channel", nextChannel)
			h.RequestNodeInfoOnChannel(cd, nextChannel)
		}
	}
}

func (h *MeshtasticHook) OnDisconnect(cl *mqtt.Client, err error, expire bool) {
	h.clientLock.Lock()
	c, ok := h.knownClients[cl.ID]
	deleted := false
	if ok && c.Address == cl.Net.Remote {
		delete(h.knownClients, cl.ID)
		deleted = true
	}
	h.clientLock.Unlock()

	if err != nil {
		h.Log.Info("client disconnected", "client", cl.ID, "expire", expire, "error", err)
	} else {
		h.Log.Info("client disconnected", "client", cl.ID, "expire", expire)
	}

	// Notify subscribers about the client disconnection
	if deleted {
		go h.notifyClientChange()
	}
}

func (h *MeshtasticHook) OnSubscribe(cl *mqtt.Client, pk packets.Packet) packets.Packet {
	// Try to set root topic from gateway subscription patterns
	h.clientLock.RLock()
	cd, ok := h.knownClients[cl.ID]
	h.clientLock.RUnlock()

	if ok && cd.IsMeshDevice() && cd.RootTopic == "" {
		// Check if subscribing to a gateway topic pattern and extract root topic
		for _, filter := range pk.Filters {
			matches := gatewaySubRegex.FindStringSubmatch(filter.Filter)
			if len(matches) > 0 {
				cd.RootTopic = matches[1] + matches[2] // e.g., "msh/US/Gateway"
				h.Log.Debug("set root topic from subscription", "client", cl.ID, "root_topic", cd.RootTopic)
				go h.notifyClientChange()
				// Trigger verification now that we have the root topic
				go h.TryVerifyNode(cl.ID, false)
				break
			}
		}
	}

	return pk
}

func (h *MeshtasticHook) OnSubscribed(cl *mqtt.Client, pk packets.Packet, reasonCodes []byte) {
	// Log each subscription with its reason code
	for i, filter := range pk.Filters {
		var reasonCode byte
		if i < len(reasonCodes) {
			reasonCode = reasonCodes[i]
		}
		status := "granted"
		if reasonCode >= 0x80 {
			status = "FAILED"
		}
		h.Log.Debug("subscription result", "client", cl.ID, "topic", filter.Filter, "requested_qos", filter.Qos, "granted_qos", reasonCode, "status", status)
	}
	h.Log.Debug(fmt.Sprintf("subscribed qos=%v", reasonCodes), "client", cl.ID, "filters", pk.Filters)
}

func (h *MeshtasticHook) OnUnsubscribed(cl *mqtt.Client, pk packets.Packet) {
	h.Log.Debug("unsubscribed", "client", cl.ID, "filters", pk.Filters)
}

func (h *MeshtasticHook) OnPublished(cl *mqtt.Client, pk packets.Packet) {
	h.Log.Debug("published to client", "client", cl.ID)

	// If this was a gateway topic from an unvalidated gateway or non-mesh device,
	// also publish to the non-gateway topic for mapping software
	if strings.HasPrefix(pk.TopicName, "msh/") {
		h.clientLock.RLock()
		cd, ok := h.knownClients[cl.ID]
		h.clientLock.RUnlock()

		if !ok {
			return
		}

		// Redirect if: non-mesh device OR mesh device that's not a valid gateway
		shouldRedirect := !cd.IsMeshDevice() || !cd.IsValidGateway()

		if shouldRedirect {
			matches := gatewayTopicRegex.FindStringSubmatch(pk.TopicName)
			if len(matches) > 0 {
				redirectedTopic := gatewayTopicRegex.ReplaceAllString(pk.TopicName, gatewayReplacement)
				h.Log.Debug("publishing to redirected topic for mapping",
					"client", cl.ID,
					"is_mesh_device", cd.IsMeshDevice(),
					"original", pk.TopicName,
					"redirected", redirectedTopic)

				// Publish to the redirected topic via the inline client asynchronously
				// This ensures mapping works while the original gateway topic message is delivered to subscribers
				// We use a goroutine to avoid deadlock from nested publish operations
				go func(topic string, payload []byte, retain bool, qos byte) {
					err := h.config.Server.Publish(topic, payload, retain, qos)
					if err != nil {
						h.Log.Error("failed to publish to redirected topic", "error", err, "topic", topic)
					}
				}(redirectedTopic, pk.Payload, pk.FixedHeader.Retain, pk.FixedHeader.Qos)
			}
		}
	}
}

func (h *MeshtasticHook) OnPublish(cl *mqtt.Client, pk packets.Packet) (packets.Packet, error) {
	h.Log.Debug("received from client", "client", cl.ID)

	if !strings.HasPrefix(pk.TopicName, "msh/") {
		return pk, nil
	}

	var env pb.ServiceEnvelope
	err := proto.Unmarshal(pk.Payload, &env)
	if err != nil {
		// Do not allow non-meshtastic payloads in the msh tree
		h.Log.Error("received non-mesh payload from client", "client", cl.ID, "payload", string(pk.Payload))
		return pk, packets.ErrRejectPacket
	}
	h.clientLock.RLock()
	cd, ok := h.knownClients[cl.ID]
	h.clientLock.RUnlock()
	if ok && cd.IsMeshDevice() {
		h.TrySetRootTopic(cd, pk.TopicName)
	}
	h.TryProcessMeshPacket(cd, &env)
	payload, err := proto.Marshal(&env)
	if err != nil {
		// Do not allow non-meshtastic payloads in the msh tree
		h.Log.Error("error re-marshalling service packet", "client", cl.ID)
		return pk, err
	}
	pkx := pk
	pkx.Payload = payload
	return pkx, nil
}

func (h *MeshtasticHook) RewriteTopicIfGateway(cd *models.ClientDetails, topic string) string {
	matches := gatewayTopicRegex.FindStringSubmatch(topic)
	if len(matches) > 0 {
		h.Log.Warn("redirecting to non-gateway topic", "username", cd.MqttUserName, "client", cd.ClientID, "topic", topic)
		topic = gatewayTopicRegex.ReplaceAllString(topic, gatewayReplacement)
	}
	return topic
}

func (h *MeshtasticHook) TrySetRootTopic(cd *models.ClientDetails, topic string) {
	matches := channelRegex.FindStringSubmatch(topic)
	if len(matches) > 0 {
		cd.RootTopic = matches[1]
		if cd.NodeDetails == nil {
			// Proxied clients don't always connect with a client ID that contains the node ID
			nid, err := meshtastic.ParseNodeID(matches[3])
			if err != nil {
				return
			}
			nodeDetails, err := h.config.Storage.NodeDB.GetNode(uint32(nid), cd.UserID)
			if err != nil {
				h.Log.Error("error loading node info", "node_id", nid, "user_id", cd.UserID, "error", err)
			} else if nodeDetails == nil {
				nodeDetails = &models.NodeInfo{NodeID: nid, UserID: cd.UserID}
			}
			cd.NodeDetails = nodeDetails
		}
		go h.TryVerifyNode(cd.ClientID, false)
	}
}

// getVerificationChannel determines which channel to use for verifying a node.
// If the node has a known primary channel, it returns that.
// Otherwise, it returns the first channel from VerificationChannels config,
// falling back to "LongFast" if no channels are configured.
func (h *MeshtasticHook) getVerificationChannel(client *models.ClientDetails) string {
	// If node already has a known primary channel, use it
	if client.NodeDetails != nil && client.NodeDetails.PrimaryChannel != "" {
		return client.NodeDetails.PrimaryChannel
	}

	// Use the first verification channel from config
	if len(h.config.MeshSettings.VerificationChannels) > 0 {
		return h.config.MeshSettings.VerificationChannels[0]
	}

	// Fallback to LongFast if no channels configured
	return "LongFast"
}

// getNextVerificationChannel returns the next channel to try after the current one.
// Returns empty string if there are no more channels to try.
func (h *MeshtasticHook) getNextVerificationChannel(currentChannel string) string {
	channels := h.config.MeshSettings.VerificationChannels
	if len(channels) == 0 {
		return ""
	}

	for i, ch := range channels {
		if ch == currentChannel && i+1 < len(channels) {
			return channels[i+1]
		}
	}
	return ""
}

func (h *MeshtasticHook) RequestNodeInfo(client *models.ClientDetails) {
	channel := h.getVerificationChannel(client)
	h.RequestNodeInfoOnChannel(client, channel)
}

func (h *MeshtasticHook) RequestNodeInfoOnChannel(client *models.ClientDetails, channel string) {
	if client.NodeDetails == nil || client.RootTopic == "" {
		return
	}

	unmess := true
	nodeInfo := pb.User{
		Id:         h.config.MeshSettings.SelfNode.NodeID.String(),
		LongName:   h.config.MeshSettings.SelfNode.LongName,
		ShortName:  h.config.MeshSettings.SelfNode.ShortName,
		IsLicensed: false,
		HwModel:    pb.HardwareModel_PRIVATE_HW,
		Role:       pb.Config_DeviceConfig_CLIENT_MUTE,
		//Macaddr:    from.ToMacAddress(),
		PublicKey:      nil,
		IsUnmessagable: &unmess,
	}

	pid, err := h.sendProtoMessage(channel, client.RootTopic, &nodeInfo, PacketInfo{
		To:           client.NodeDetails.NodeID,
		PortNum:      pb.PortNum_NODEINFO_APP,
		Encrypted:    PSKEncryption,
		WantResponse: true,
		WantAck:      true,
	})
	if err == nil {
		h.config.Server.Log.Info("verification packet sent to node", "node", client.NodeDetails.NodeID, "client", client.ClientID, "topic_root", client.RootTopic, "channel", channel)
		client.SetVerificationPending(pid, channel)

		// Schedule a check for channel timeout to try the next channel if needed
		clientID := client.ClientID
		go func() {
			// Wait for channel timeout plus a small buffer
			time.Sleep(models.ChannelVerifyTimeout + 5*time.Second)
			h.TryVerifyNode(clientID, false)
		}()
	}
}
