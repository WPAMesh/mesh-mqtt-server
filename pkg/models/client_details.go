package models

import (
	"fmt"
	"sync"
	"time"

	meshtastic "github.com/kabili207/mesh-mqtt-server/pkg/meshtastic"
	pb "github.com/kabili207/mesh-mqtt-server/pkg/meshtastic/generated"
)

const (
	MaxValidationAge = 3 * 24 * time.Hour
)

type MeshMqttServer interface {
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
}

type NodeInfo struct {
	NodeID       meshtastic.NodeID `db:"node_id"`
	UserID       int               `db:"user_id"`
	LongName     string            `db:"long_name"`
	ShortName    string            `db:"short_name"`
	NodeRole     string            `db:"node_role"`
	LastSeen     *time.Time        `db:"last_seen"`
	VerifiedDate *time.Time        `db:"last_verified"`
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

func (c *ClientDetails) SetVerificationPending(packetID uint32) {
	c.VerifyPacketID = packetID
	if packetID == 0 {
		c.VerifyReqTime = nil
	} else {
		now := time.Now()
		c.VerifyReqTime = &now
	}
}

func (c *ClientDetails) IsPendingVerification() bool {
	if c.VerifyReqTime != nil {
		expireDate := c.VerifyReqTime.Add(5 * time.Minute)
		return time.Now().Before(expireDate)
	}
	return false
}

func (c *ClientDetails) IsVerified() bool {
	return c.NodeDetails != nil && c.NodeDetails.IsVerified()
}

func (c *ClientDetails) IsValidGateway() bool {
	return c.NodeDetails != nil && c.ProxyType == "" && c.IsVerified() &&
		c.NodeDetails.NodeRole != "" &&
		c.NodeDetails.NodeRole != pb.Config_DeviceConfig_CLIENT_MUTE.String() &&
		c.NodeDetails.NodeRole != pb.Config_DeviceConfig_ROUTER_CLIENT.String()
}

func (c *ClientDetails) SyncUserID() {
	if c.NodeDetails != nil {
		c.NodeDetails.UserID = c.UserID
	}
}

func (c *ClientDetails) GetValidationErrors() []string {
	errs := []string{}
	if c.ProxyType != "" {
		errs = append(errs, "Node is connected via client proxy")
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
	if !c.IsVerified() {
		errs = append(errs, "Downlink over LongFast has not been verified")
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

func (c *NodeInfo) IsVerified() bool {
	if c.VerifiedDate != nil {
		expireDate := c.VerifiedDate.Add(MaxValidationAge)
		return time.Now().Before(expireDate)
	}
	return false
}
