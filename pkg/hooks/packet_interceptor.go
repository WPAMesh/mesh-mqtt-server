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
		h.config.Server.Log.Info("node downlink verified", "node", client.NodeDetails.NodeID, "client", client.ClientID, "topic", client.RootTopic, "channel", client.VerifyChannel)
		// Clear pending verification state
		client.SetVerificationPending(0, "")
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
	if !c.IsDownlinkVerified() || c.IsExpiringSoon() {
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
			}
		}
	}
	if save {
		err := h.config.Storage.NodeDB.SaveInfo(c.NodeDetails)
		if err != nil {
			h.config.Server.Log.Error("error updating node info", "node", c.NodeDetails.NodeID, "client", c.ClientID, "error", err)
			return
		}
	}
	// TODO: Update database record as well
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

func (c *MeshtasticHook) insertUnknownHops(packet *pb.MeshPacket, disco *pb.RouteDiscovery, isTowardsDestination bool) {
	// Insert unknown
	var routeCount = 0
	var snrCount = 0
	var route *[]uint32
	var snrList *[]int32

	if isTowardsDestination {
		routeCount = len(disco.Route)
		snrCount = len(disco.SnrTowards)
		route = &disco.Route
		snrList = &disco.SnrTowards
	} else {
		routeCount = len(disco.RouteBack)
		snrCount = len(disco.SnrBack)
		route = &disco.RouteBack
		snrList = &disco.SnrBack
	}

	if packet.HopStart != 0 && packet.HopLimit <= packet.HopStart {
		hopsTaken := packet.HopStart - packet.HopLimit
		diff := int(hopsTaken) - routeCount

		for i := 0; i < diff; i++ {
			if routeCount < len(*route) {
				r := append(*route, meshtastic.BROADCAST_ID)
				route = &r
				routeCount += 1
			}
		}

		diff = routeCount - snrCount
		for i := 0; i < diff; i++ {
			if snrCount < len(*snrList) {
				s := append(*snrList, math.MinInt8) // Min == SNR Unknown
				snrList = &s
				snrCount += 1
			}
		}
	}
}
