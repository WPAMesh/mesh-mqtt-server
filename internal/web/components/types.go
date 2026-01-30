package components

// PortNumStatsData holds packet counts for a specific port number
type PortNumStatsData struct {
	PortNum     int32  `json:"port_num"`
	PortName    string `json:"port_name"`
	WithFlag    uint64 `json:"with_flag"`
	WithoutFlag uint64 `json:"without_flag"`
}

// OkToMqttStatsData holds OK to MQTT statistics for a gateway
type OkToMqttStatsData struct {
	TotalWithFlag    uint64             `json:"total_with_flag"`
	TotalWithoutFlag uint64             `json:"total_without_flag"`
	ByPortNum        []PortNumStatsData `json:"by_port_num,omitempty"`
}

// NodeData represents a node for display and API responses
type NodeData struct {
	NodeID           string             `json:"node_id"`
	ShortName        string             `json:"short_name"`
	LongName         string             `json:"long_name"`
	NodeColor        string             `json:"node_color,omitempty"`
	ProxyType        string             `json:"proxy_type"`
	Address          string             `json:"address"`
	RootTopic        string             `json:"root_topic"`
	NodeRole         string             `json:"node_role,omitempty"`
	HwModel          string             `json:"hw_model,omitempty"`
	LastSeen         *string            `json:"last_seen,omitempty"`
	IsDownlink       bool               `json:"is_downlink"`
	IsValidGateway   bool               `json:"is_valid_gateway"`
	IsConnected      bool               `json:"is_connected"`
	IsMeshDevice     bool               `json:"is_mesh_device"`
	ClientID         string             `json:"client_id"`
	UserDisplay      string             `json:"user_display,omitempty"`
	ValidationErrors []string           `json:"validation_errors,omitempty"`
	OkToMqttStats    *OkToMqttStatsData `json:"ok_to_mqtt_stats,omitempty"`
}

// OtherClientData represents a non-mesh client for display and API responses
type OtherClientData struct {
	ClientID    string `json:"client_id"`
	Address     string `json:"address"`
	UserDisplay string `json:"user_display,omitempty"`
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
}

// AllNodesPageData holds all data for the all nodes page
type AllNodesPageData struct {
	Nodes            []NodeData
	OtherClients     []OtherClientData
	IsSuperuser      bool
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
