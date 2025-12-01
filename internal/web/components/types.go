package components

// NodeData represents a node for display
type NodeData struct {
	NodeID           string
	ShortName        string
	LongName         string
	NodeColor        string
	ProxyType        string
	Address          string
	RootTopic        string
	NodeRole         string
	HwModel          string
	LastSeen         *string
	IsDownlink       bool
	IsValidGateway   bool
	IsConnected      bool
	IsMeshDevice     bool
	ClientID         string
	UserDisplay      string
	ValidationErrors []string
}

// OtherClientData represents a non-mesh client for display
type OtherClientData struct {
	ClientID    string
	Address     string
	UserDisplay string
}

// MqttConfigData holds MQTT configuration for display
type MqttConfigData struct {
	ServerAddress string
	Username      string
	Password      string
	RootTopic     string
	GatewayTopic  string
	Channels      []ChannelInfo
}

// ChannelInfo holds channel configuration
type ChannelInfo struct {
	Name   string
	PSK    string
	Export bool
}

// MyNodesPageData holds all data for the my nodes page
type MyNodesPageData struct {
	Nodes          []NodeData
	OtherClients   []OtherClientData
	MqttConfig     *MqttConfigData
	ShowOnboarding bool
	IsSuperuser    bool
	SSEEndpoint    string
}

// AllNodesPageData holds all data for the all nodes page
type AllNodesPageData struct {
	Nodes            []NodeData
	OtherClients     []OtherClientData
	IsSuperuser      bool
	SSEEndpoint      string
	ForwardingStatus *ForwardingStatusData
}

// UsersPageData holds data for the users page
type UsersPageData struct {
	IsSuperuser bool
}

// ForwardingTargetData holds forwarding target status for display
type ForwardingTargetData struct {
	Name          string
	Address       string
	Connected     bool
	LastError     string
	LastErrorTime string
	ConnectedAt   string
	Topics        []string
}

// ForwardingStatusData holds forwarding status for display
type ForwardingStatusData struct {
	Enabled bool
	Targets []ForwardingTargetData
}
