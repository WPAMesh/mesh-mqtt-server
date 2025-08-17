package models

import "fmt"

type MeshMqttServer interface {
	GetUserClients(userID string) []*ClientDetails
}

type ClientDetails struct {
	UserID    string
	ClientID  string
	NodeID    string
	LongName  string
	ShortName string
	ProxyType string
	Address   string
}

func (c *ClientDetails) IsMeshDevice() bool {
	return c.NodeID != "" || c.ProxyType != ""
}

func (c *ClientDetails) GetDisplayName() string {
	return fmt.Sprintf("%s (%s)", c.LongName, c.ShortName)
}
