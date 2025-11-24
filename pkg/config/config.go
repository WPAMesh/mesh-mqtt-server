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
