package hooks

import (
	"math"
	"slices"
	"time"

	"github.com/kabili207/mesh-mqtt-server/pkg/meshtastic"
	pb "github.com/kabili207/mesh-mqtt-server/pkg/meshtastic/generated"
	"github.com/kabili207/mesh-mqtt-server/pkg/meshtastic/radio"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
	"google.golang.org/protobuf/proto"
)

func (h *MeshtasticHook) TryProcessMeshPacket(client *models.ClientDetails, env *pb.ServiceEnvelope) bool {

	pkt := env.GetPacket()
	if pkt == nil {
		return false
	}
	shouldReencrypt := true
	switch pkt.GetPayloadVariant().(type) {
	case *pb.MeshPacket_Decoded:
		shouldReencrypt = false
	}
	decoded, err := radio.TryDecode(pkt, radio.DefaultKey)
	if err != nil || decoded == nil {
		return false
	}

	if decoded.Bitfield == nil || *decoded.Bitfield&uint32(BITFIELD_OkToMQTT) == 0 {
		// Check if this packet is from the gateway node itself (not relayed)
		sendingNode := meshtastic.NodeID(pkt.From)
		isFromGateway := env.GatewayId == sendingNode.String()

		if isFromGateway && client != nil && client.IsMeshDevice() {
			// Flag that this gateway is sending packets without OkToMQTT
			if !client.HasMissingOkToMqtt {
				client.HasMissingOkToMqtt = true
				h.Log.Warn("gateway sending packets without OkToMQTT bit",
					"client", client.ClientID,
					"node", sendingNode,
					"portnum", decoded.Portnum.String())
			}

			// Log if this would have been a verification response
			if client.IsPendingVerification() && decoded.RequestId == client.VerifyPacketID {
				h.Log.Warn("dropping potential verification response due to missing OkToMQTT bit",
					"client", client.ClientID,
					"portnum", decoded.Portnum.String(),
					"request_id", decoded.RequestId,
					"from", sendingNode)
			}
		}
		return false
	}

	h.processMeshPacket(client, env, decoded)

	if !shouldReencrypt {
		pkt.PayloadVariant = &pb.MeshPacket_Decoded{
			Decoded: decoded,
		}
	} else {
		rawData, err := proto.Marshal(decoded)
		if err != nil {
			return false
		}
		rawData, err = radio.XOR(rawData, radio.DefaultKey, pkt.Id, pkt.From)
		if err != nil {
			return false
		}
		pkt.PayloadVariant = &pb.MeshPacket_Encrypted{
			Encrypted: rawData,
		}
	}

	env.Packet = pkt

	return true
}

func (h *MeshtasticHook) processMeshPacket(client *models.ClientDetails, env *pb.ServiceEnvelope, data *pb.Data) {
	h.checkPacketVerification(client, env, data)
	switch data.Portnum {
	case pb.PortNum_TRACEROUTE_APP:
		var r = pb.RouteDiscovery{}
		err := proto.Unmarshal(data.Payload, &r)
		if err == nil {
			h.processTraceroute(env, data, &r)
			payload, err := proto.Marshal(&r)
			if err == nil {
				data.Payload = payload
			}
		}
	case pb.PortNum_NODEINFO_APP:
		var u = pb.User{}
		err := proto.Unmarshal(data.Payload, &u)
		if err == nil {
			go h.processNodeInfo(client, env, data, &u)
		}
	}

}

func (h *MeshtasticHook) checkPacketVerification(client *models.ClientDetails, env *pb.ServiceEnvelope, data *pb.Data) {

	if client == nil || !client.IsMeshDevice() {
		return
	}
	pkt := env.GetPacket()
	if pkt == nil {
		return
	}
	sendingNode := meshtastic.NodeID(pkt.From)

	if env.GatewayId != sendingNode.String() {
		return
	}

	if client.IsPendingVerification() && data.RequestId == client.VerifyPacketID {

		if client.NodeDetails == nil {
			nodeDetails, err := h.config.Storage.NodeDB.GetNode(uint32(sendingNode), client.UserID)
			if err != nil {
				h.Log.Error("error loading node info", "node_id", sendingNode, "user_id", client.UserID, "error", err)
			} else if nodeDetails == nil {
				nodeDetails = &models.NodeInfo{NodeID: sendingNode, UserID: client.UserID}
			}
			client.NodeDetails = nodeDetails
		}

		client.NodeDetails.VerifiedDate = radio.Ptr(time.Now())
		// Record the channel that successfully verified as the primary channel
		if client.VerifyChannel != "" {
			client.NodeDetails.PrimaryChannel = client.VerifyChannel
		}
		err := h.config.Storage.NodeDB.SaveInfo(client.NodeDetails)
		if err != nil {
			h.config.Server.Log.Error("error updating node info", "node", client.NodeDetails.NodeID, "client", client.ClientID, "error", err)
			return
		}
		h.config.Server.Log.Info("node downlink verified", "node", client.NodeDetails.NodeID, "client", client.ClientID, "topic", client.RootTopic, "channel", client.VerifyChannel, "via_portnum", data.Portnum.String())
		// Clear pending verification state
		client.SetVerificationPending(0, "")
		// Notify subscribers about the verification status change
		go h.notifyClientChange()
	}
}

func (h *MeshtasticHook) processNodeInfo(c *models.ClientDetails, env *pb.ServiceEnvelope, data *pb.Data, user *pb.User) {

	if c == nil || !c.IsMeshDevice() {
		// The only time this should happen is when a client sends a node info
		// and immediately loses connection
		return
	}

	if c.NodeDetails == nil {
		// Proxied clients don't always connect with a client ID that contains the node ID
		nid, err := meshtastic.ParseNodeID(env.GatewayId)
		if err != nil {
			return
		}
		nodeDetails, err := h.config.Storage.NodeDB.GetNode(uint32(nid), c.UserID)
		if err != nil {
			h.Log.Error("error loading node info", "node_id", nid, "user_id", c.UserID, "error", err)
		} else if nodeDetails == nil {
			nodeDetails = &models.NodeInfo{NodeID: nid, UserID: c.UserID}
		}
		c.NodeDetails = nodeDetails
	}

	//clientNode, _ := meshtastic.ParseNodeID(c.NodeID)
	if c.NodeDetails.NodeID.String() != user.Id {
		// Relayed from the mesh, we don't care about it
		return
	}
	c.SyncUserID()

	// Track if node role changed (affects gateway validation)
	oldRole := c.NodeDetails.NodeRole
	wasValidGateway := c.IsValidGateway()

	c.NodeDetails.LongName = user.LongName
	c.NodeDetails.ShortName = user.ShortName
	c.NodeDetails.NodeRole = user.Role.String()
	c.NodeDetails.LastSeen = radio.Ptr(time.Now())

	// Log if role changed (important for gateway validation)
	if oldRole != "" && oldRole != c.NodeDetails.NodeRole {
		isValidGateway := c.IsValidGateway()
		h.Log.Info("node role changed",
			"node", c.NodeDetails.NodeID,
			"client", c.ClientID,
			"old_role", oldRole,
			"new_role", c.NodeDetails.NodeRole,
			"was_valid_gateway", wasValidGateway,
			"is_valid_gateway", isValidGateway)
	}

	save := true
	if c.NeedsVerification() {
		if !c.IsPendingVerification() {
			go h.TryVerifyNode(c.ClientID, false)
		} else {
			if data.RequestId == c.VerifyPacketID {
				c.NodeDetails.VerifiedDate = radio.Ptr(time.Now())
				// Record the channel that successfully verified as the primary channel
				if c.VerifyChannel != "" {
					c.NodeDetails.PrimaryChannel = c.VerifyChannel
				}
				err := h.config.Storage.NodeDB.SaveInfo(c.NodeDetails)
				if err != nil {
					h.config.Server.Log.Error("error updating node info", "node", c.NodeDetails.NodeID, "client", c.ClientID, "error", err)
					return
				}
				save = false
				h.config.Server.Log.Info("node downlink verified", "node", c.NodeDetails.NodeID, "client", c.ClientID, "topic", c.RootTopic, "channel", c.VerifyChannel)
				// Clear pending verification state
				c.SetVerificationPending(0, "")
				// Notify subscribers about the verification status change
				go h.notifyClientChange()
			}
		}
	}
	if save {
		err := h.config.Storage.NodeDB.SaveInfo(c.NodeDetails)
		if err != nil {
			h.config.Server.Log.Error("error updating node info", "node", c.NodeDetails.NodeID, "client", c.ClientID, "error", err)
			return
		}
		// Notify subscribers about node info change
		go h.notifyClientChange()
	}
}

func (c *MeshtasticHook) processTraceroute(env *pb.ServiceEnvelope, data *pb.Data, disco *pb.RouteDiscovery) {

	isTowardsDestination := data.RequestId == 0
	c.insertUnknownHops(env.Packet, disco, isTowardsDestination)

	gatewayNode, err := meshtastic.ParseNodeID(env.GetGatewayId())
	if err != nil {
		return
	}

	packet := env.Packet

	// Gateway node isn't always included in the route list, so ensure we add it
	if gatewayNode != 0 && uint32(gatewayNode) != packet.From {
		node := uint32(gatewayNode)
		snr := int32(packet.RxSnr * 4)
		var route *[]uint32
		var snrs *[]int32

		if isTowardsDestination {
			route, snrs = &disco.Route, &disco.SnrTowards
		} else {
			route, snrs = &disco.RouteBack, &disco.SnrBack
		}

		if !slices.Contains(*route, node) {
			*route = append(*route, node)
			*snrs = append(*snrs, snr)
		}
	}
}

// maxRouteSize matches the firmware's ROUTE_SIZE constant (max entries in route arrays)
const maxRouteSize = 8

func (c *MeshtasticHook) insertUnknownHops(packet *pb.MeshPacket, disco *pb.RouteDiscovery, isTowardsDestination bool) {
	// Calculate hops taken, matching firmware's getHopsAway logic
	hopsTaken := c.getHopsAway(packet)
	if hopsTaken < 0 {
		return
	}

	if isTowardsDestination {
		// Insert unknown hops into route/snr_towards
		diff := hopsTaken - len(disco.Route)
		for i := 0; i < diff; i++ {
			if len(disco.Route) < maxRouteSize {
				disco.Route = append(disco.Route, meshtastic.BROADCAST_ID)
			}
		}
		// Pad SNR array to match route length
		diff = len(disco.Route) - len(disco.SnrTowards)
		for i := 0; i < diff; i++ {
			if len(disco.SnrTowards) < maxRouteSize {
				disco.SnrTowards = append(disco.SnrTowards, math.MinInt8)
			}
		}
	} else {
		// Insert unknown hops into route_back/snr_back
		diff := hopsTaken - len(disco.RouteBack)
		for i := 0; i < diff; i++ {
			if len(disco.RouteBack) < maxRouteSize {
				disco.RouteBack = append(disco.RouteBack, meshtastic.BROADCAST_ID)
			}
		}
		// Pad SNR array to match route length
		diff = len(disco.RouteBack) - len(disco.SnrBack)
		for i := 0; i < diff; i++ {
			if len(disco.SnrBack) < maxRouteSize {
				disco.SnrBack = append(disco.SnrBack, math.MinInt8)
			}
		}
	}
}

// getHopsAway calculates how many hops the packet has traveled, matching firmware logic.
// Returns -1 if hops cannot be reliably determined.
func (c *MeshtasticHook) getHopsAway(packet *pb.MeshPacket) int {
	// Firmware prior to 2.3.0 lacked hop_start. Firmware 2.5.0+ has bitfield always present.
	// If hop_start is 0 and no bitfield, we can't determine hops.
	decoded, isDecoded := packet.GetPayloadVariant().(*pb.MeshPacket_Decoded)
	hasBitfield := isDecoded && decoded.Decoded.Bitfield != nil

	if packet.HopStart == 0 && !hasBitfield {
		return -1
	}

	// Guard against invalid values
	if packet.HopStart < packet.HopLimit {
		return -1
	}

	return int(packet.HopStart - packet.HopLimit)
}
