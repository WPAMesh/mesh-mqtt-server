package hooks

import (
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"time"

	meshtastic "github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	"github.com/kabili207/meshtastic-go/core/lora"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

type EncryptionType int

const (
	NoEncryption EncryptionType = iota
	PSKEncryption
	PKIEncryption
)

type BitFieldMask uint32

const (
	BITFIELD_OkToMQTT     BitFieldMask = 1
	BITFIELD_WantResponse BitFieldMask = 2

	DefaultHopLimit = 3
)

type PacketInfo struct {
	PortNum            pb.PortNum
	Encrypted          EncryptionType
	To                 meshtastic.NodeID
	RequestId, ReplyId uint32
	WantResponse       bool
	WantAck            bool
	Emoji              bool
}

func (c *MeshtasticHook) generatePacketId() uint32 {
	// Based on the official packet generation method
	// https://github.com/meshtastic/firmware/blob/03f19bca0e9e456342dfb0397a805404677e5abc/src/mesh/Router.cpp#L98

	rollingPacketId := c.currentPacketId

	if rollingPacketId == 0 {
		rollingPacketId = rand.Uint32()
	}

	rollingPacketId++
	c.currentPacketId = (rollingPacketId & (math.MaxUint32 >> 22)) | (rand.Uint32() << 10)
	return c.currentPacketId
}

func (c *MeshtasticHook) sendProtoMessage(channel string, rootTopic string, message proto.Message, info PacketInfo) (packetID uint32, err error) {
	rawInfo, err := proto.Marshal(message)
	if err != nil {
		return 0, err
	}
	id, err := c.sendBytes(channel, rootTopic, rawInfo, info)
	return id, err
}

func (c *MeshtasticHook) sendBytes(channel string, rootTopic string, rawInfo []byte, info PacketInfo) (packetID uint32, err error) {

	bitfield := uint32(BITFIELD_OkToMQTT)

	emojiVal := 0
	if info.Emoji {
		emojiVal = 1
	}

	// While most devices seem to just ignore payloads that are too large, one of my devices
	// on an older firmware had part of it's memory corrupted and started broadcasting different
	// node info on every boot, adding junk node IDs the device db of nearby nodes
	if len(rawInfo) > int(pb.Constants_DATA_PAYLOAD_LEN)-1 {
		return 0, fmt.Errorf("message is too large for meshtastic network: max(%d) sent(%d)", int(pb.Constants_DATA_PAYLOAD_LEN)-1, len(rawInfo))
	}

	data := pb.Data{
		Portnum:   info.PortNum,
		Payload:   rawInfo,
		Bitfield:  &bitfield,
		RequestId: info.RequestId,
		ReplyId:   info.ReplyId,
		Emoji:     uint32(emojiVal),
	}

	if info.WantResponse && info.To != meshtastic.NodeID(meshtastic.BroadcastNodeID) && (info.PortNum == pb.PortNum_NODEINFO_APP || info.PortNum == pb.PortNum_POSITION_APP) {
		data.WantResponse = true
		bits := *data.Bitfield | uint32(BITFIELD_WantResponse)
		data.Bitfield = &bits
	}

	wantAck := info.WantAck

	now := time.Now()
	msgTime := uint32(now.Unix())

	packetId := c.generatePacketId()

	rawData, err := proto.Marshal(&data)
	if err != nil {
		return 0, err
	}

	key := crypto.DefaultKey

	channelHash, _ := crypto.ChannelHash(channel, key)

	maxHops := 0

	pkt := pb.MeshPacket{
		Id:       packetId,
		To:       uint32(info.To),
		From:     uint32(c.config.MeshSettings.SelfNode.NodeID),
		HopLimit: uint32(0),
		HopStart: uint32(maxHops),
		ViaMqtt:  false,
		WantAck:  wantAck,
		RxTime:   msgTime,
		RxSnr:    0,
		RxRssi:   0,
		Channel:  channelHash,
		Priority: lora.GetPriority(&data, wantAck),
		Delayed:  pb.MeshPacket_NO_DELAY,
	}

	switch info.Encrypted {
	case NoEncryption:
		pkt.Channel = 0
		pkt.PayloadVariant = &pb.MeshPacket_Decoded{
			Decoded: &data,
		}
	case PSKEncryption:
		encodedBytes, err := crypto.XOR(rawData, key, packetId, uint32(c.config.MeshSettings.SelfNode.NodeID))
		if err != nil {
			return packetId, err
		}
		pkt.PayloadVariant = &pb.MeshPacket_Encrypted{
			Encrypted: encodedBytes,
		}
	default:
		return 0, errors.New("unknown encryption method requested")
	}

	env := pb.ServiceEnvelope{
		ChannelId: channel,
		GatewayId: c.config.MeshSettings.SelfNode.NodeID.String(),
		Packet:    &pkt,
	}

	rawEnv, err := proto.Marshal(&env)
	if err != nil {
		return 0, err
	}

	// We can process packets significantly faster than actual hardware, so we
	// need to ensure other nodes have time to switch their radios between modes
	// to transmit and receive
	time.Sleep(200 * time.Millisecond)

	topic := fmt.Sprintf("%s/2/e/%s/%s", rootTopic, channel, c.config.MeshSettings.SelfNode.NodeID.String())

	// Publish asynchronously to avoid potential deadlocks from nested hook calls
	go func(t string, payload []byte) {
		err := c.config.Server.Publish(t, payload, false, 0)
		if err != nil {
			c.Log.Error("failed to publish message", "error", err, "topic", t)
		}
	}(topic, rawEnv)

	return packetId, nil

}
