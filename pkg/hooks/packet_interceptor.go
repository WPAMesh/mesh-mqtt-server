package hooks

import (
	"math"
	"slices"
	"time"

	"github.com/kabili207/mesh-mqtt-server/pkg/models"
	"github.com/kabili207/mesh-mqtt-server/pkg/util"
	meshtastic "github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/mochi-mqtt/server/v2/packets"
	"google.golang.org/protobuf/proto"
)

func (h *MeshtasticHook) TryProcessMeshPacket(client *models.ClientDetails, env *pb.ServiceEnvelope) (bool, error) {

	pkt := env.GetPacket()
	if pkt == nil {
		return false, packets.ErrRejectPacket
	}
	shouldReencrypt := true
	switch pkt.GetPayloadVariant().(type) {
	case *pb.MeshPacket_Decoded:
		shouldReencrypt = false
	}
	decoded, err := crypto.TryDecode(pkt, crypto.DefaultKey)
	if err != nil || decoded == nil {
		return false, nil
	}

	// Check if this packet is from the gateway node itself (not relayed)
	sendingNode := meshtastic.NodeID(pkt.From)
	isFromGateway := env.GatewayId == sendingNode.String()
	hasOkToMqtt := decoded.Bitfield != nil && *decoded.Bitfield&uint32(BITFIELD_OkToMQTT) != 0

	// MAP_REPORT packets are only sent over MQTT, so firmware doesn't set the OkToMQTT flag.
	// Treat these as if they have the flag set since this is expected behavior.
	if decoded.Portnum == pb.PortNum_MAP_REPORT_APP {
		hasOkToMqtt = true
	}

	// Track stats for packets from the gateway node itself
	if isFromGateway && client != nil && client.IsMeshDevice() {
		client.OkToMqttStats.RecordPacket(int32(decoded.Portnum), hasOkToMqtt)
	}

	if !hasOkToMqtt {
		if isFromGateway && client != nil && client.IsMeshDevice() {
			wasViolating := client.OkToMqttViolations.HasRecentViolation(time.Now())
			client.OkToMqttViolations.RecordViolation(time.Now())
			if !wasViolating {
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
		return false, packets.ErrRejectPacket
	}

	h.processMeshPacket(client, env, decoded)

	if !shouldReencrypt {
		pkt.PayloadVariant = &pb.MeshPacket_Decoded{
			Decoded: decoded,
		}
	} else {
		rawData, err := proto.Marshal(decoded)
		if err != nil {
			return false, packets.ErrRejectPacket
		}
		rawData, err = crypto.XOR(rawData, crypto.DefaultKey, pkt.Id, pkt.From)
		if err != nil {
			return false, packets.ErrRejectPacket
		}
		pkt.PayloadVariant = &pb.MeshPacket_Encrypted{
			Encrypted: rawData,
		}
	}

	env.Packet = pkt

	return true, nil
}

func (h *MeshtasticHook) processMeshPacket(client *models.ClientDetails, env *pb.ServiceEnvelope, data *pb.Data) {
	h.checkPacketVerification(client, env, data)
	switch data.Portnum {
	case pb.PortNum_TRACEROUTE_APP:
		var r = pb.RouteDiscovery{}
		err := proto.Unmarshal(data.Payload, &r)
		if err == nil {
			h.processTraceroute(env, data, &r)
			h.sendTraceRouteToMeshSense(client, env, &r)
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
			h.sendNodeInfoToMeshSense(client, env, &u)
		}
	case pb.PortNum_POSITION_APP:
		var pos = pb.Position{}
		err := proto.Unmarshal(data.Payload, &pos)
		if err == nil {
			go h.processPosition(client, env, &pos)
			h.sendPositionToMeshSense(client, env, &pos)
		}
	case pb.PortNum_TELEMETRY_APP:
		var tel = pb.Telemetry{}
		err := proto.Unmarshal(data.Payload, &tel)
		if err == nil {
			h.sendTelemetryToMeshSense(client, env, &tel)
		}
	case pb.PortNum_TEXT_MESSAGE_APP:
		h.sendTextMessageToMeshSense(client, env)
	case pb.PortNum_MAP_REPORT_APP:
		var report = pb.MapReport{}
		err := proto.Unmarshal(data.Payload, &report)
		if err == nil {
			go h.processMapReport(client, env, &report)
		}
	}

}

// sendToMeshSense sends a node update to the MeshSense server if configured.
// The client parameter is used to resolve the node's short name when available.
func (h *MeshtasticHook) sendToMeshSense(client *models.ClientDetails, env *pb.ServiceEnvelope, updates map[string]any) {
	if h.config.MeshSense == nil {
		return
	}
	pkt := env.GetPacket()
	if pkt == nil {
		return
	}
	updates["num"] = pkt.From
	hops := h.getHopsAway(pkt)
	if hops >= 0 {
		updates["hopsAway"] = hops
	}
	// Ensure name is always present — MeshSense requires it
	if _, ok := updates["name"]; !ok {
		nodeID := meshtastic.NodeID(pkt.From)
		name := nodeID.DefaultShortName()
		if client != nil && client.NodeDetails != nil && client.NodeDetails.NodeID == nodeID {
			if sn := client.NodeDetails.ShortName; sn != "" {
				name = sn
			}
		}
		updates["name"] = name
	}
	go h.config.MeshSense.SendUpdate(pkt.From, updates)
}

func (h *MeshtasticHook) sendNodeInfoToMeshSense(client *models.ClientDetails, env *pb.ServiceEnvelope, user *pb.User) {
	h.sendToMeshSense(client, env, map[string]any{
		"name": user.ShortName,
		"user": map[string]any{
			"id":        user.Id,
			"longName":  user.LongName,
			"shortName": user.ShortName,
			"hwModel":   user.HwModel.String(),
			"role":      user.Role.String(),
		},
	})
}

func (h *MeshtasticHook) sendPositionToMeshSense(client *models.ClientDetails, env *pb.ServiceEnvelope, pos *pb.Position) {
	posData := map[string]any{}
	if pos.LatitudeI != nil {
		posData["latitudeI"] = *pos.LatitudeI
	}
	if pos.LongitudeI != nil {
		posData["longitudeI"] = *pos.LongitudeI
	}
	if pos.Altitude != nil {
		posData["altitude"] = *pos.Altitude
	}
	if pos.Time != 0 {
		posData["time"] = pos.Time
	}
	if len(posData) == 0 {
		return
	}
	h.sendToMeshSense(client, env, map[string]any{
		"position": posData,
	})
}

func (h *MeshtasticHook) sendTelemetryToMeshSense(client *models.ClientDetails, env *pb.ServiceEnvelope, tel *pb.Telemetry) {
	updates := map[string]any{}
	switch v := tel.GetVariant().(type) {
	case *pb.Telemetry_DeviceMetrics:
		dm := v.DeviceMetrics
		metrics := map[string]any{}
		if dm.BatteryLevel != nil {
			metrics["batteryLevel"] = *dm.BatteryLevel
		}
		if dm.Voltage != nil {
			metrics["voltage"] = *dm.Voltage
		}
		if dm.ChannelUtilization != nil {
			metrics["channelUtilization"] = *dm.ChannelUtilization
		}
		if dm.AirUtilTx != nil {
			metrics["airUtilTx"] = *dm.AirUtilTx
		}
		if dm.UptimeSeconds != nil {
			metrics["uptimeSeconds"] = *dm.UptimeSeconds
		}
		updates["deviceMetrics"] = metrics
	case *pb.Telemetry_EnvironmentMetrics:
		em := v.EnvironmentMetrics
		metrics := map[string]any{}
		if em.Temperature != nil {
			metrics["temperature"] = *em.Temperature
		}
		if em.RelativeHumidity != nil {
			metrics["relativeHumidity"] = *em.RelativeHumidity
		}
		if em.BarometricPressure != nil {
			metrics["barometricPressure"] = *em.BarometricPressure
		}
		if em.GasResistance != nil {
			metrics["gasResistance"] = *em.GasResistance
		}
		if em.Iaq != nil {
			metrics["iaq"] = *em.Iaq
		}
		updates["environmentMetrics"] = metrics
	default:
		return
	}
	h.sendToMeshSense(client, env, updates)
}

func (h *MeshtasticHook) sendTraceRouteToMeshSense(client *models.ClientDetails, env *pb.ServiceEnvelope, disco *pb.RouteDiscovery) {
	h.sendToMeshSense(client, env, map[string]any{
		"trace": map[string]any{
			"route":      disco.Route,
			"snrTowards": disco.SnrTowards,
			"routeBack":  disco.RouteBack,
			"snrBack":    disco.SnrBack,
		},
	})
}

func (h *MeshtasticHook) sendTextMessageToMeshSense(client *models.ClientDetails, env *pb.ServiceEnvelope) {
	pkt := env.GetPacket()
	if pkt == nil {
		return
	}
	h.sendToMeshSense(client, env, map[string]any{
		"lastHeard": pkt.RxTime,
	})
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
			nodeDetails, err := h.config.Storage.NodeDB.GetNode(uint32(sendingNode))
			if err != nil {
				h.Log.Error("error loading node info", "node_id", sendingNode, "user_id", client.UserID, "error", err)
			} else if nodeDetails == nil {
				nodeDetails = &models.NodeInfo{NodeID: sendingNode, UserID: &client.UserID}
			}
			client.NodeDetails = nodeDetails
		}

		client.NodeDetails.VerifiedDate = util.Ptr(time.Now())
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
		go h.config.AuthHook.NotifyClientChange()
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
		nodeDetails, err := h.config.Storage.NodeDB.GetNode(uint32(nid))
		if err != nil {
			h.Log.Error("error loading node info", "node_id", nid, "user_id", c.UserID, "error", err)
		} else if nodeDetails == nil {
			nodeDetails = &models.NodeInfo{NodeID: nid, UserID: &c.UserID}
		}
		c.NodeDetails = nodeDetails
	}

	//clientNode, _ := meshtastic.ParseNodeID(c.NodeID)
	if c.NodeDetails.NodeID.String() != user.Id {
		// Relayed from the mesh — save identity to the mesh-wide node DB
		nid, err := meshtastic.ParseNodeID(user.Id)
		if err == nil {
			go func() {
				if err := h.config.Storage.NodeDB.SaveNodeIdentity(uint32(nid), user.LongName, user.ShortName, user.Role.String(), user.HwModel.String()); err != nil {
					h.Log.Error("error saving overheard node identity", "node_id", nid, "error", err)
				}
			}()
		}
		return
	}
	c.SyncUserID()

	// Track if node role changed (affects gateway validation)
	oldRole := c.NodeDetails.NodeRole
	wasValidGateway := c.IsValidGateway()

	c.NodeDetails.LongName = user.LongName
	c.NodeDetails.ShortName = user.ShortName
	c.NodeDetails.NodeRole = user.Role.String()
	c.NodeDetails.LastSeen = util.Ptr(time.Now())

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
				c.NodeDetails.VerifiedDate = util.Ptr(time.Now())
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
				go h.config.AuthHook.NotifyClientChange()
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
		go h.config.AuthHook.NotifyClientChange()
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
				disco.Route = append(disco.Route, uint32(meshtastic.BroadcastNodeID))
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
				disco.RouteBack = append(disco.RouteBack, uint32(meshtastic.BroadcastNodeID))
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

func (h *MeshtasticHook) processPosition(c *models.ClientDetails, env *pb.ServiceEnvelope, pos *pb.Position) {
	if c == nil || !c.IsMeshDevice() {
		return
	}

	pkt := env.GetPacket()
	if pkt == nil {
		return
	}

	sendingNode := meshtastic.NodeID(pkt.From)
	if env.GatewayId != sendingNode.String() {
		// Relayed position — save to mesh-wide node DB if valid
		if pos.LatitudeI != nil && pos.LongitudeI != nil {
			lat := float64(*pos.LatitudeI) * 1e-7
			lon := float64(*pos.LongitudeI) * 1e-7
			go func() {
				node, err := h.config.Storage.NodeDB.GetNode(uint32(sendingNode))
				if err != nil {
					h.Log.Error("error loading overheard node", "node_id", sendingNode, "error", err)
					return
				}
				if node == nil {
					node = &models.NodeInfo{NodeID: sendingNode}
				}
				node.Latitude = &lat
				node.Longitude = &lon
				node.LastSeen = util.Ptr(time.Now())
				if err := h.config.Storage.NodeDB.SaveInfo(node); err != nil {
					h.Log.Error("error saving overheard node position", "node_id", sendingNode, "error", err)
				}
			}()
		}
		return
	}

	if pos.LatitudeI == nil || pos.LongitudeI == nil {
		return
	}

	lat := float64(*pos.LatitudeI) * 1e-7
	lon := float64(*pos.LongitudeI) * 1e-7

	if c.NodeDetails == nil {
		nid, err := meshtastic.ParseNodeID(env.GatewayId)
		if err != nil {
			return
		}
		nodeDetails, err := h.config.Storage.NodeDB.GetNode(uint32(nid))
		if err != nil {
			h.Log.Error("error loading node info", "node_id", nid, "user_id", c.UserID, "error", err)
			return
		} else if nodeDetails == nil {
			nodeDetails = &models.NodeInfo{NodeID: nid, UserID: &c.UserID}
		}
		c.NodeDetails = nodeDetails
	}

	c.NodeDetails.Latitude = &lat
	c.NodeDetails.Longitude = &lon
	c.NodeDetails.LastSeen = util.Ptr(time.Now())

	err := h.config.Storage.NodeDB.SaveInfo(c.NodeDetails)
	if err != nil {
		h.Log.Error("error saving node position", "node", c.NodeDetails.NodeID, "client", c.ClientID, "error", err)
		return
	}
	h.Log.Info("updated node position", "node", c.NodeDetails.NodeID, "lat", lat, "lon", lon)
}

func (h *MeshtasticHook) processMapReport(c *models.ClientDetails, env *pb.ServiceEnvelope, report *pb.MapReport) {
	if c == nil || !c.IsMeshDevice() {
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

	if report.LatitudeI == 0 && report.LongitudeI == 0 {
		return
	}

	lat := float64(report.LatitudeI) * 1e-7
	lon := float64(report.LongitudeI) * 1e-7

	if c.NodeDetails == nil {
		nid, err := meshtastic.ParseNodeID(env.GatewayId)
		if err != nil {
			return
		}
		nodeDetails, err := h.config.Storage.NodeDB.GetNode(uint32(nid))
		if err != nil {
			h.Log.Error("error loading node info", "node_id", nid, "user_id", c.UserID, "error", err)
			return
		} else if nodeDetails == nil {
			nodeDetails = &models.NodeInfo{NodeID: nid, UserID: &c.UserID}
		}
		c.NodeDetails = nodeDetails
	}

	c.NodeDetails.Latitude = &lat
	c.NodeDetails.Longitude = &lon
	c.NodeDetails.LastSeen = util.Ptr(time.Now())

	err := h.config.Storage.NodeDB.SaveInfo(c.NodeDetails)
	if err != nil {
		h.Log.Error("error saving node position from map report", "node", c.NodeDetails.NodeID, "client", c.ClientID, "error", err)
		return
	}
	h.Log.Info("updated node position from map report", "node", c.NodeDetails.NodeID, "lat", lat, "lon", lon)
}
