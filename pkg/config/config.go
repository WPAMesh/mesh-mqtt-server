package config

import (
	meshtastic "github.com/kabili207/meshtastic-go/core"
	"golang.org/x/oauth2"
)

type Configuration struct {
	ListenAddr    string
	SessionSecret string
	BaseURL       string
	LogLevel      string
	LogFormat     string
	OAuth         struct {
		Discord oauth2.Config
	}
	Discord      DiscordSettings
	MeshSettings MeshSettings
	MeshCore     MeshCoreSettings
	Forwarding   ForwardingSettings
	MeshSense    MeshSenseSettings
	Database     struct {
		User     string
		Password string
		Host     string
		DB       string
	}
}

// DiscordSettings configures Discord guild membership and role-based access
type DiscordSettings struct {
	// GuildID is the Discord server ID for membership verification
	GuildID string
	// AdminRoleID is the Discord role ID that grants admin access (optional)
	AdminRoleID string
	// BotToken is the Discord bot token for background role syncing (optional).
	// When set alongside AdminRoleID, the server periodically checks each
	// registered user's Discord roles and updates their admin status.
	BotToken string
}

type MeshSettings struct {
	MqttRoot string
	Channels []MeshChannelDef
	// VerificationChannels is an ordered list of channel names to try when
	// verifying a node's downlink capability. The server will try each channel
	// in order until it receives a response. Once a node responds, its primary
	// channel is recorded and used for future verification attempts.
	VerificationChannels []string
	// DisableGatewayTopics forces all clients to use non-gateway topics.
	// When enabled, gateway topic subscriptions are rejected and gateway
	// publishes are redirected to the corresponding non-gateway topic.
	// This effectively disables the gateway functionality system-wide.
	DisableGatewayTopics bool
	SelfNode             struct {
		NodeID    meshtastic.NodeID
		LongName  string
		ShortName string
	}
	RateLimit RateLimitSettings
}

// RateLimitSettings configures per-node packet rate limiting.
// Limits how many unique packets a single mesh node can send within a time window.
// Duplicate packets (same packet ID from different gateways) are always allowed
// through, since mapping software uses them for RF path analysis.
type RateLimitSettings struct {
	// Enabled controls whether per-node rate limiting is active
	Enabled bool
	// MaxPackets is the maximum number of unique packets allowed per node per window
	MaxPackets int
	// Window is the time window duration (e.g., "1m", "30s")
	Window string
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
	// Topic is the MQTT topic for raw-bytes protocol (new firmware).
	// If set, packets are received as raw bytes instead of base64.
	// Example: "meshcore/bridge"
	Topic string
	// TopicPrefix is the MQTT topic prefix for MeshCore packets (legacy base64 protocol).
	// Used when Topic is not set. Default: "meshcore"
	TopicPrefix string
	// Observer configures ingest of MeshCore observer telemetry, published by
	// clients such as meshcore-room-server in the meshcoretomqtt JSON format.
	Observer MeshCoreObserverSettings
}

// MeshCoreObserverSettings configures ingest of MeshCore observer telemetry.
// Observers publish JSON status and per-packet messages to
// {TopicPrefix}/{IATA}/{PUBKEY}/{status,packets} and authenticate with a
// "v1_<PUBKEY>" username plus an Ed25519-signed JWT or nonce password.
type MeshCoreObserverSettings struct {
	// Enabled controls whether observer clients may connect and be ingested.
	Enabled bool
	// TopicPrefix is the first segment of observer topics. Default: "meshcore"
	TopicPrefix string
	// RequireAudience, when non-empty, rejects observer JWTs whose "aud" claim
	// does not match this value (typically the broker hostname). Empty skips
	// the audience check. It does not apply to nonce-based auth.
	RequireAudience string
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

// MeshSenseSettings configures forwarding node data to a MeshSense instance
type MeshSenseSettings struct {
	// Enabled controls whether MeshSense forwarding is active
	Enabled bool
	// URL is the MeshSense server URL (default: "https://meshsense.affirmatech.com")
	URL string
}

