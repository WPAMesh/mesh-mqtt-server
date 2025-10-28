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
	InvalidPackets int
	ValidGWChecker func() bool
	// Cached permissions with expiry - revalidated after TTL
	cachedIsSuperuser      bool
	cachedIsGatewayAllowed bool
	permissionsCachedAt    time.Time
}

type NodeInfo struct {
	NodeID       meshtastic.NodeID `db:"node_id"`
	UserID       int               `db:"user_id"`
	LongName     string            `db:"long_name"`
	ShortName    string            `db:"short_name"`
	NodeRole     string            `db:"node_role"`
	HwModel      string            `db:"hw_model"`
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
		expireDate := c.VerifyReqTime.Add(15 * time.Minute)
		return time.Now().Before(expireDate)
	}
	return false
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

	if c.ValidGWChecker != nil && !c.ValidGWChecker() {
		errs = append(errs, "Gateway not allowed by mesh admin")
	}
	if c.ProxyType != "" {
		errs = append(errs, "Node is connected via client proxy")
	}
	if !c.IsUsingGatewayTopic() {
		errs = append(errs, "Not using a gateway route topic")
	} else if !c.IsDownlinkVerified() {
		errs = append(errs, "Downlink over LongFast has not been verified")
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

// Permission cache TTL - match the user store's 15 minute TTL
const PermissionCacheTTL = 15 * time.Minute

// GetCachedPermissions returns cached permissions if still valid, or (false, false, false) if expired
func (c *ClientDetails) GetCachedPermissions() (isSuperuser, isGatewayAllowed, valid bool) {
	c.RLock()
	defer c.RUnlock()

	if time.Since(c.permissionsCachedAt) > PermissionCacheTTL {
		return false, false, false
	}

	return c.cachedIsSuperuser, c.cachedIsGatewayAllowed, true
}

// SetCachedPermissions updates the cached permissions with current timestamp
func (c *ClientDetails) SetCachedPermissions(isSuperuser, isGatewayAllowed bool) {
	c.Lock()
	defer c.Unlock()

	c.cachedIsSuperuser = isSuperuser
	c.cachedIsGatewayAllowed = isGatewayAllowed
	c.permissionsCachedAt = time.Now()
}
