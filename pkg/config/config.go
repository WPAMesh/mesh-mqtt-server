package config

import (
	meshtastic "github.com/kabili207/meshtastic-go/core"
	"golang.org/x/oauth2"
)

type Configuration struct {
	ListenAddr    string
	SessionSecret string
	BaseURL       string
	OAuth         struct {
		Discord oauth2.Config
	}
	MeshSettings MeshSettings
	MeshCore     MeshCoreSettings
	Forwarding   ForwardingSettings
	Bridge       BridgeSettings
	Database     struct {
		User     string
		Password string
		Host     string
		DB       string
	}
}

type MeshSettings struct {
	MqttRoot string
	Channels []MeshChannelDef
	// VerificationChannels is an ordered list of channel names to try when
	// verifying a node's downlink capability. The server will try each channel
	// in order until it receives a response. Once a node responds, its primary
	// channel is recorded and used for future verification attempts.
	VerificationChannels []string
	SelfNode             struct {
		NodeID    meshtastic.NodeID
		LongName  string
		ShortName string
	}
}

type MeshChannelDef struct {
	Name   string
	Key    string
	Export bool
}

// MeshCoreSettings configures MeshCore protocol support
type MeshCoreSettings struct {
	// Enabled controls whether MeshCore packet processing is active
	Enabled bool
	// TopicPrefix is the MQTT topic prefix for MeshCore packets (default: "meshcore")
	TopicPrefix string
}

// ForwardingSettings configures MQTT packet forwarding to external servers
type ForwardingSettings struct {
	Enabled bool
	Targets []ForwardingTarget
}

// ForwardingTarget defines a single external MQTT server to forward packets to
type ForwardingTarget struct {
	// Name is a friendly identifier for this target (used in logs and status)
	Name string
	// Address is the MQTT broker address (e.g., "mqtt.example.com:1883")
	Address string
	// Username for MQTT authentication (optional)
	Username string
	// Password for MQTT authentication (optional)
	Password string
	// UseTLS enables TLS connection to the broker
	UseTLS bool
	// Topics is a list of topic patterns to forward (e.g., ["msh/#"])
	Topics []string
	// TopicRewrites defines topic transformation rules
	// Key is the pattern to match, value is the replacement
	// Example: {"msh/US": "msh/forwarded/US"} rewrites "msh/US/..." to "msh/forwarded/US/..."
	TopicRewrites map[string]string
	// ClientID is the MQTT client ID to use (auto-generated if empty)
	ClientID string
}

// BridgeSettings configures bidirectional bridging between Meshtastic and MeshCore
type BridgeSettings struct {
	// Enabled controls whether bridging is active
	Enabled bool
	// MeshID is this bridge's mesh ID used for outbound messages (e.g., "wpamesh-mqtt")
	MeshID string
	// TopicPrefix is the MQTT topic prefix for MeshCore packets (default: "meshcore")
	TopicPrefix string
	// HopLimit is the max hops for packets bridged to Meshtastic (default: 3, max: 7).
	// The bridge consumes one hop, so packets are sent with HopStart=HopLimit, HopLimit=HopLimit-1.
	HopLimit int
	// ChannelMappings defines which Meshtastic channels map to which MeshCore channels
	ChannelMappings []ChannelMapping
	// MeshtasticPrefix is prepended to messages bridged TO MeshCore (e.g., "[MT] ")
	MeshtasticPrefix string
	// MeshCorePrefix is prepended to messages bridged TO Meshtastic (e.g., "[MC] ")
	MeshCorePrefix string
	// ParseSenderName attempts to extract "Name: message" format from MeshCore messages
	ParseSenderName bool
}

// ChannelMapping defines a mapping between a Meshtastic channel and MeshCore channel
type ChannelMapping struct {
	// MeshtasticChannel is the channel name (e.g., "LongFast")
	MeshtasticChannel string
	// MeshtasticTopicRoot is the MQTT topic root (e.g., "msh/US")
	MeshtasticTopicRoot string
	// MeshCoreChannelKey is the base64-encoded shared key for MeshCore encryption/decryption
	MeshCoreChannelKey string
	// Direction controls which way messages are bridged: "both", "mt_to_mc", "mc_to_mt"
	Direction string
}
