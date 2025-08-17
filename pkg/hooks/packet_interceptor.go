package hooks

import (
	"math"
	"slices"

	"github.com/kabili207/mesh-mqtt-server/pkg/meshtastic"
	pb "github.com/kabili207/mesh-mqtt-server/pkg/meshtastic/generated"
	"github.com/kabili207/mesh-mqtt-server/pkg/meshtastic/radio"
	"google.golang.org/protobuf/proto"
)

func (h *MeshtasticHook) TryProcessMeshPacket(clientID string, env *pb.ServiceEnvelope) bool {

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

	h.processMeshPacket(clientID, env, decoded)

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

func (h *MeshtasticHook) processMeshPacket(clientID string, env *pb.ServiceEnvelope, data *pb.Data) {
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
			go h.processNodeInfo(clientID, env, &u)
		}
	}

}

func (h *MeshtasticHook) processNodeInfo(clientID string, env *pb.ServiceEnvelope, user *pb.User) {
	h.clientLock.RLock()
	defer h.clientLock.RUnlock()
	c, ok := h.knownClients[clientID]
	if !ok || !c.IsMeshDevice() {
		// The only time this should happen is when a client sends a node info
		// and immediately loses connection
		return
	}

	if c.NodeID == "" {
		// Proxied clients don't always connect with a client ID that contains the node ID
		c.NodeID = env.GatewayId
	}

	//clientNode, _ := meshtastic.ParseNodeID(c.NodeID)
	if c.NodeID != user.Id {
		// Relayed from the mesh, we don't care about it
		return
	}
	c.LongName = user.LongName
	c.ShortName = user.ShortName
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
