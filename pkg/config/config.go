package config

import (
	"github.com/kabili207/mesh-mqtt-server/pkg/meshtastic"
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
	Forwarding   ForwardingSettings
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
