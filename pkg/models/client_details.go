package models

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	meshtastic "github.com/kabili207/mesh-mqtt-server/pkg/meshtastic"
	pb "github.com/kabili207/mesh-mqtt-server/pkg/meshtastic/generated"
)

const (
	MaxValidationAge = 3 * 24 * time.Hour
	// ChannelVerifyTimeout is how long to wait for a response on a single channel
	// before trying the next channel in the verification channel list.
	ChannelVerifyTimeout = 60 * time.Second
	// MaxVerifyTimeout is the overall timeout for verification attempts across all channels.
	MaxVerifyTimeout = 15 * time.Minute
)

type MeshMqttServer interface {
	GetAllClients() []*ClientDetails
	GetUserClients(userID string) []*ClientDetails
}

type ClientDetails struct {
	sync.RWMutex
	MqttUserName   string
	UserID         int
	ClientID       string
	NodeDetails    *NodeInfo
	ProxyType      string
	Address        string
	RootTopic      string
	VerifyPacketID uint32
	VerifyReqTime  *time.Time
	VerifyChannel  string // Channel used for the current verification request
	InvalidPackets int
	ValidGWChecker func() bool
}

type NodeInfo struct {
	NodeID         meshtastic.NodeID `db:"node_id"`
	UserID         int               `db:"user_id"`
	LongName       string            `db:"long_name"`
	ShortName      string            `db:"short_name"`
	NodeRole       string            `db:"node_role"`
	HwModel        string            `db:"hw_model"`
	PrimaryChannel string            `db:"primary_channel"`
	LastSeen       *time.Time        `db:"last_seen"`
	VerifiedDate   *time.Time        `db:"last_verified"`
}

func (c *ClientDetails) IsMeshDevice() bool {
	return c.NodeDetails != nil || c.ProxyType != ""
}

func (c *ClientDetails) GetDisplayName() string {
	if c.NodeDetails != nil {
		return c.NodeDetails.GetDisplayName()
	}
	if c.IsMeshDevice() {
		return "unknown"
	}
	return c.ClientID
}

func (c *ClientDetails) GetLongName() string {
	if c.NodeDetails != nil {
		return c.NodeDetails.GetSafeLongName()
	}
	return "unknown"
}

func (c *ClientDetails) GetShortName() string {
	if c.NodeDetails != nil {
		return c.NodeDetails.GetSafeShortName()
	}
	return ""
}

func (c *ClientDetails) SetVerificationPending(packetID uint32, channel string) {
	c.VerifyPacketID = packetID
	c.VerifyChannel = channel
	if packetID == 0 {
		c.VerifyReqTime = nil
		c.VerifyChannel = ""
	} else {
		now := time.Now()
		c.VerifyReqTime = &now
	}
}

func (c *ClientDetails) IsPendingVerification() bool {
	if c.VerifyReqTime != nil {
		expireDate := c.VerifyReqTime.Add(MaxVerifyTimeout)
		return time.Now().Before(expireDate)
	}
	return false
}

// ShouldTryNextChannel returns true if a verification request is pending but the
// per-channel timeout has expired, indicating we should try the next channel.
func (c *ClientDetails) ShouldTryNextChannel() bool {
	if c.VerifyReqTime == nil || c.VerifyChannel == "" {
		return false
	}
	channelExpireDate := c.VerifyReqTime.Add(ChannelVerifyTimeout)
	overallExpireDate := c.VerifyReqTime.Add(MaxVerifyTimeout)
	now := time.Now()
	// Channel timeout expired but overall verification window still open
	return now.After(channelExpireDate) && now.Before(overallExpireDate)
}

func (c *ClientDetails) IsExpiringSoon() bool {
	return c.NodeDetails == nil || c.NodeDetails.IsExpiringSoon()
}

func (c *ClientDetails) IsDownlinkVerified() bool {
	return c.NodeDetails != nil && c.NodeDetails.IsDownlinkVerified()
}

func (c *ClientDetails) IsUsingGatewayTopic() bool {
	return strings.HasSuffix(c.RootTopic, "/Gateway")
}

func (c *ClientDetails) IsValidGateway() bool {
	extValid := true
	if c.ValidGWChecker != nil {
		extValid = c.ValidGWChecker()
	}
	return extValid && c.NodeDetails != nil && c.ProxyType == "" && c.IsDownlinkVerified() &&
		c.IsUsingGatewayTopic() && c.NodeDetails.NodeRole != "" &&
		c.NodeDetails.NodeRole != pb.Config_DeviceConfig_CLIENT_MUTE.String() &&
		c.NodeDetails.NodeRole != pb.Config_DeviceConfig_ROUTER_CLIENT.String()

}

func (c *ClientDetails) SyncUserID() {
	if c.NodeDetails != nil {
		c.NodeDetails.UserID = c.UserID
	}
}

func (c *ClientDetails) GetIPAddress() (string, error) {
	host, _, err := net.SplitHostPort(c.Address)
	return host, err
}

func (c *ClientDetails) GetNodeID() *meshtastic.NodeID {
	if c.NodeDetails != nil && !c.NodeDetails.NodeID.IsReservedID() {
		return &c.NodeDetails.NodeID
	}
	return nil
}

func (c *ClientDetails) GetValidationErrors() []string {
	errs := []string{}

	// Check gateway permission (ValidGWChecker uses database cache)
	if c.ValidGWChecker != nil && !c.ValidGWChecker() {
		errs = append(errs, "Gateway not allowed by mesh admin")
	}
	if c.ProxyType != "" {
		errs = append(errs, "Node is connected via client proxy")
	}
	if !c.IsUsingGatewayTopic() {
		errs = append(errs, "Not using a gateway root topic")
	} else if !c.IsDownlinkVerified() {
		channelName := "primary channel"
		if c.NodeDetails != nil && c.NodeDetails.PrimaryChannel != "" {
			channelName = c.NodeDetails.PrimaryChannel
		}
		errs = append(errs, fmt.Sprintf("Downlink over %s has not been verified", channelName))
	}
	if c.NodeDetails == nil {
		errs = append(errs, "Node info not received yet")
	} else if c.NodeDetails.NodeRole == "" {
		errs = append(errs, "Node role not yet known")
	} else if c.NodeDetails.NodeRole == pb.Config_DeviceConfig_CLIENT_MUTE.String() {
		errs = append(errs, fmt.Sprintf("Invalid node role: %s", pb.Config_DeviceConfig_CLIENT_MUTE.String()))
	} else if c.NodeDetails.NodeRole == pb.Config_DeviceConfig_ROUTER_CLIENT.String() {
		errs = append(errs, fmt.Sprintf("Deprecated node role: %s", pb.Config_DeviceConfig_ROUTER_CLIENT.String()))
	}

	return errs
}

func (c *NodeInfo) GetDisplayName() string {
	if c.LongName != "" {
		return fmt.Sprintf("%s (%s)", c.LongName, c.ShortName)
	}
	long, short := c.NodeID.GetDefaultNodeNames()
	return fmt.Sprintf("%s (%s)", long, short)
}

func (c *NodeInfo) GetSafeLongName() string {
	if c.LongName != "" {
		return c.LongName
	}
	long, _ := c.NodeID.GetDefaultNodeNames()
	return long
}

func (c *NodeInfo) GetSafeShortName() string {
	if c.ShortName != "" {
		return c.ShortName
	}
	_, short := c.NodeID.GetDefaultNodeNames()
	return short
}

func (c *NodeInfo) IsDownlinkVerified() bool {
	if c.VerifiedDate != nil {
		expireDate := c.VerifiedDate.Add(MaxValidationAge)
		return time.Now().Before(expireDate)
	}
	return false
}

func (c *NodeInfo) IsExpiringSoon() bool {
	if c.VerifiedDate != nil {
		expireDate := c.VerifiedDate.Add(MaxValidationAge / 3)
		return time.Now().After(expireDate)
	}
	return true
}

func (n *NodeInfo) GetNodeColor() string {
	r, g, b := n.NodeID.GetNodeColor()
	return fmt.Sprintf("%d, %d, %d", r, g, b)
}

