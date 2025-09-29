package hooks

import (
	"bytes"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"

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

// Options contains configuration settings for the hook.
type MeshtasticHookOptions struct {
	Server       *mqtt.Server
	Storage      *store.Stores
	MeshSettings config.MeshSettings
}

var _ models.MeshMqttServer = (*MeshtasticHook)(nil)

type MeshtasticHook struct {
	mqtt.HookBase
	config          *MeshtasticHookOptions
	knownClients    map[string]*models.ClientDetails
	clientLock      sync.RWMutex
	currentPacketId uint32
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

	hash, salt := generateHashAndSalt("9VT#iTb2h&7Cs&RZkUYg")
	log.Printf("Hash: %s", hash)
	log.Printf("Salt: %s", salt)

	return nil
}

func (h *MeshtasticHook) GetAllClients() []*models.ClientDetails {
	userClients := []*models.ClientDetails{}
	h.clientLock.RLock()
	defer h.clientLock.RUnlock()

	for _, c := range h.knownClients {
		userClients = append(userClients, c)
	}

	return userClients
}

func (h *MeshtasticHook) GetUserClients(mqttUser string) []*models.ClientDetails {
	userClients := []*models.ClientDetails{}
	h.clientLock.RLock()
	defer h.clientLock.RUnlock()

	for _, c := range h.knownClients {
		if c.MqttUserName == mqttUser {
			userClients = append(userClients, c)
		}
	}

	return userClients
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
		h.knownClients[clientID] = &models.ClientDetails{
			MqttUserName: user,
			ClientID:     clientID,
			UserID:       validatedUser.ID,
			NodeDetails:  nodeDetails,
			ProxyType:    proxyType,
			Address:      cl.Net.Remote,
		}
		h.clientLock.Unlock()
		if nodeDetails != nil {
			h.Log.Info("client authenticated", "username", user, "client", clientID, "node", nodeDetails.GetDisplayName(), "proxy", proxyType)
			go h.TryVerifyNode(cl.ID, false)
		} else {

			h.Log.Info("client authenticated", "username", user, "client", clientID, "proxy", proxyType)
		}
	}
	if validatedUser == nil {
		h.Log.Warn("authentication failed", "username", user, "remote_addr", cl.Net.Remote)
	}
	return validatedUser != nil
}

// OnACLCheck returns true if the connecting client has matching read or write access to subscribe
// or publish to a given topic.
func (h *MeshtasticHook) OnACLCheck(cl *mqtt.Client, topic string, write bool) bool {

	h.clientLock.RLock()
	cd, ok := h.knownClients[cl.ID]
	h.clientLock.RUnlock()
	if !ok {
		h.Log.Warn("unknown client in ACL check",
			"client", cl.ID,
			"username", string(cl.Properties.Username),
			"topic", topic)
		return false
	}

	isSU, _ := h.config.Storage.Users.IsSuperuser(cd.UserID)

	if sysFilter.FilterMatches(topic) {
		return isSU
	}

	if !cd.IsMeshDevice() {
		// Non-mesh devices are only allowed to read, unless they are superuser
		return isSU || !write
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
	//h.Log.Info("Gateway read check:", "client", cd.ClientID, "is_write", write, "gatewayTopic", isAllowed, "topic", topic)
	return write || isAllowed
}

func (h *MeshtasticHook) checkGatewayACL(cd *models.ClientDetails, topic string, write bool) bool {
	if !strings.HasPrefix(topic, "msh/") {
		return false
	}
	if write {
		return true
	}

	matches := gatewayPublishRegex.FindStringSubmatch(topic)
	if len(matches) > 0 {
		gwAllowed, err := h.config.Storage.Users.IsGatewayAllowed(cd.UserID)
		if err != nil {
			h.Log.Error("unable to check if user permitted to use gateway", "client", cd.ClientID)
			return false
		}
		if pubID, err := meshtastic.ParseNodeID(matches[3]); err == nil {
			if pubID == h.config.MeshSettings.SelfNode.NodeID || cd.IsValidGateway(gwAllowed) {
				return true
			}
			h.Log.Info("Not forwarding packet to invalid gateway:", "client", cd.ClientID, "topic", topic)
			return false
		}
	}

	if gatewaySubRegex.MatchString(topic) {
		return true
	}

	return false
}

// subscribeCallback handles messages for subscribed topics
func (h *MeshtasticHook) subscribeCallback(cl *mqtt.Client, sub packets.Subscription, pk packets.Packet) {
	h.Log.Debug("hook subscribed message", "client", cl.ID, "topic", pk.TopicName)
}

func (h *MeshtasticHook) OnConnect(cl *mqtt.Client, pk packets.Packet) error {
	h.Log.Debug("client connected", "client", cl.ID)

	return nil
}

func (h *MeshtasticHook) TryVerifyNode(clientID string, force bool) {
	h.clientLock.Lock()
	cd, ok := h.knownClients[clientID]
	h.clientLock.Unlock()

	if ok {
		cd.RLock()
		shouldReq := cd.IsUsingGatewayTopic() && !cd.IsPendingVerification() && (!cd.IsVerified() || cd.IsExpiringSoon() || force)
		cd.RUnlock()
		if shouldReq {
			cd.Lock()
			defer cd.Unlock()
			h.RequestNodeInfo(cd)
			return
		}
	}
}

func (h *MeshtasticHook) OnDisconnect(cl *mqtt.Client, err error, expire bool) {
	h.clientLock.Lock()
	c, ok := h.knownClients[cl.ID]
	if ok && c.Address == cl.Net.Remote {
		delete(h.knownClients, cl.ID)
	}
	h.clientLock.Unlock()
	if err != nil {
		h.Log.Info("client disconnected", "client", cl.ID, "expire", expire, "error", err)
	} else {
		h.Log.Info("client disconnected", "client", cl.ID, "expire", expire)
	}

}

func (h *MeshtasticHook) OnSubscribe(cl *mqtt.Client, pk packets.Packet) packets.Packet {

	return pk
}

func (h *MeshtasticHook) OnSubscribed(cl *mqtt.Client, pk packets.Packet, reasonCodes []byte) {
	h.Log.Debug(fmt.Sprintf("subscribed qos=%v", reasonCodes), "client", cl.ID, "filters", pk.Filters)
}

func (h *MeshtasticHook) OnUnsubscribed(cl *mqtt.Client, pk packets.Packet) {
	h.Log.Debug("unsubscribed", "client", cl.ID, "filters", pk.Filters)
}

func (h *MeshtasticHook) OnPublished(cl *mqtt.Client, pk packets.Packet) {
	h.Log.Debug("published to client", "client", cl.ID)
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
	gwAllowed, err := h.config.Storage.Users.IsGatewayAllowed(cd.UserID)
	if err != nil {
		h.Log.Error("unable to check if user permitted to use gateway", "client", cl.ID)
		return pk, err
	}
	if ok && cd.IsMeshDevice() && !cd.IsValidGateway(gwAllowed) {
		pkx.TopicName = h.RewriteTopicIfGateway(cd, pk.TopicName)
	}
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

func (h *MeshtasticHook) RequestNodeInfo(client *models.ClientDetails) {

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

	pid, err := h.sendProtoMessage("LongFast", client.RootTopic, &nodeInfo, PacketInfo{
		To:           client.NodeDetails.NodeID,
		PortNum:      pb.PortNum_NODEINFO_APP,
		Encrypted:    PSKEncryption,
		WantResponse: true,
		WantAck:      true,
	})
	if err == nil {
		h.config.Server.Log.Info("verification packet sent to node", "node", client.NodeDetails.NodeID, "client", client.ClientID, "topic_root", client.RootTopic)
		client.SetVerificationPending(pid)
	}
}
