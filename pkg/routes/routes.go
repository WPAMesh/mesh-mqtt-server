package routes

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"sort"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/kabili207/mesh-mqtt-server/internal/web"
	"github.com/kabili207/mesh-mqtt-server/internal/web/components"
	"github.com/kabili207/mesh-mqtt-server/pkg/auth"
	"github.com/kabili207/mesh-mqtt-server/pkg/config"
	"github.com/kabili207/mesh-mqtt-server/pkg/hooks"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
	"github.com/kabili207/mesh-mqtt-server/pkg/store"
	"golang.org/x/oauth2"
)

const (
	sessionName = "mesht_mqtt"
)

var DiscordEndpoint = oauth2.Endpoint{
	AuthURL:  "https://discord.com/oauth2/authorize",
	TokenURL: "https://discord.com/api/oauth2/token",
}

type WebRouter struct {
	config         config.Configuration
	storage        store.Stores
	sessionStore   *sessions.CookieStore
	MqttServer     models.MeshMqttServer
	ClientNotifier *ClientNotifier
	ForwardingHook *hooks.ForwardingHook
}

func (wr *WebRouter) getSession(r *http.Request) (*sessions.Session, error) {
	return wr.sessionStore.Get(r, sessionName)
}

// Push the given resource to the client.
func push(w http.ResponseWriter, resource string) {
	pusher, ok := w.(http.Pusher)
	if ok {
		if err := pusher.Push(resource, nil); err == nil {
			return
		}
	}
}

func (wr *WebRouter) Initialize(config config.Configuration, store store.Stores) error {
	wr.storage = store
	wr.sessionStore = sessions.NewCookieStore([]byte(config.SessionSecret))
	wr.ClientNotifier = NewClientNotifier()
	//wr.sessionStore.Options.Secure = false
	config.OAuth.Discord.RedirectURL = config.BaseURL + "/auth/discord/callback"
	config.OAuth.Discord.Scopes = []string{
		"identify",
		"guilds",
		"guilds.members.read",
	}
	config.OAuth.Discord.Endpoint = DiscordEndpoint
	wr.config = config

	return wr.handleRequests(config.ListenAddr)
}

type Alert struct {
	Type    string
	Message string
	Detail  *string
}

type MqttConfigData struct {
	ServerAddress string
	Username      string
	Password      string
	RootTopic     string
	GatewayTopic  string
	Channels      []ChannelInfo
}

type ChannelInfo struct {
	Name   string
	PSK    string
	Export bool
}

type PageVariables struct {
	PageTitle      string
	Alerts         []Alert
	ConnectedNodes []*models.ClientDetails
	OtherClients   []*models.ClientDetails
	MqttConfig     *MqttConfigData
	ShowOnboarding bool
	IsSuperuser    bool
}

func (wr *WebRouter) handleRequests(listenAddr string) error {
	// creates a new instance of a mux router
	myRouter := mux.NewRouter().StrictSlash(true)

	//staticFS, _ := fs.Sub(web.ContentFS, "static")

	myRouter.HandleFunc("/", wr.homePage)
	myRouter.HandleFunc("/all-nodes", wr.allNodes)
	myRouter.HandleFunc("/users", wr.usersPage)
	myRouter.HandleFunc("/login", wr.loginPage)
	myRouter.HandleFunc("/api/set-mqtt-password", wr.setMqttPassword).Methods("POST")
	myRouter.HandleFunc("/api/nodes", wr.getNodes).Methods("GET")
	myRouter.HandleFunc("/api/nodes-html", wr.nodesHTML).Methods("GET")
	myRouter.HandleFunc("/api/nodes-sse", wr.nodesSSE).Methods("GET")
	myRouter.HandleFunc("/api/users", wr.getUsers).Methods("GET")
	myRouter.HandleFunc("/api/users-html", wr.usersHTML).Methods("GET")
	myRouter.HandleFunc("/api/users/{id}", wr.updateUser).Methods("PUT")
	myRouter.HandleFunc("/api/users/{id}", wr.deleteUser).Methods("DELETE")
	myRouter.HandleFunc("/api/forwarding/status", wr.getForwardingStatus).Methods("GET")
	myRouter.HandleFunc("/auth/logout", wr.userLogoutHandler)
	myRouter.HandleFunc("/auth/discord/login", wr.discordLoginHandler)
	myRouter.HandleFunc("/auth/discord/callback", wr.discordCallbackHandler)
	staticFS, _ := fs.Sub(web.ContentFS, "static")
	myRouter.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServerFS(staticFS)))

	myRouter.Use(handlers.ProxyHeaders)
	myRouter.Use(RequestLogger)
	h := handlers.RecoveryHandler()

	return http.ListenAndServe(listenAddr, h(myRouter))
}

func RequestLogger(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		slog.Info("endpoint hit", "method", r.Method, "path", r.URL.Path, "remote_host", r.RemoteAddr, "user_agent", r.UserAgent())
		// Call the next handler in the chain.
		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func (wr *WebRouter) loginPage(w http.ResponseWriter, r *http.Request) {
	session, err := wr.getSession(r)
	user, err := wr.getUser(session)
	if err == nil && user != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	err = components.LoginPage().Render(r.Context(), w)
	if err != nil {
		slog.Error("error rendering login page", "error", err)
		http.Error(w, "Error rendering page", 500)
	}
}

func (wr *WebRouter) homePage(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	nodes, otherClients := wr.getNodesData(user, false, true, false)

	mqttConfig := wr.getTemplMqttConfig(r, user)
	showOnboarding := user.PasswordHash == "" // Show onboarding if no password set

	pageData := components.MyNodesPageData{
		Nodes:          nodes,
		OtherClients:   otherClients,
		MqttConfig:     mqttConfig,
		ShowOnboarding: showOnboarding,
		IsSuperuser:    user.IsSuperuser,
		SSEEndpoint:    "/api/nodes-sse?filter-connected=on",
	}

	if err := components.MyNodesPage(pageData).Render(r.Context(), w); err != nil {
		slog.Error("error rendering my_nodes page", "error", err)
		http.Error(w, "Error rendering page", 500)
	}
}

func (wr *WebRouter) allNodes(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !user.IsSuperuser {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	nodes, otherClients := wr.getNodesData(user, true, true, false)

	pageData := components.AllNodesPageData{
		Nodes:            nodes,
		OtherClients:     otherClients,
		IsSuperuser:      true,
		SSEEndpoint:      "/api/nodes-sse?all_users=true&filter-connected=on",
		ForwardingStatus: wr.getForwardingStatusData(),
	}

	if err := components.AllNodesPage(pageData).Render(r.Context(), w); err != nil {
		slog.Error("error rendering all_nodes page", "error", err)
		http.Error(w, "Error rendering page", 500)
	}
}

func (wr *WebRouter) getUserDisplay(mqttUsername string) string {
	user, err := wr.storage.Users.GetByUserName(mqttUsername)
	if err != nil || user == nil {
		return mqttUsername
	}
	if user.DisplayName != nil && *user.DisplayName != "" {
		return *user.DisplayName
	}
	return mqttUsername
}

func (wr *WebRouter) getMqttConfig(r *http.Request, user *models.User) *MqttConfigData {
	if user == nil {
		return nil
	}

	channels := make([]ChannelInfo, len(wr.config.MeshSettings.Channels))
	for i, ch := range wr.config.MeshSettings.Channels {
		channels[i] = ChannelInfo{
			Name:   ch.Name,
			PSK:    ch.Key,
			Export: ch.Export,
		}
	}

	url := r.URL
	url.Host = r.Host
	return &MqttConfigData{
		ServerAddress: url.Hostname(),
		Username:      user.UserName,
		Password:      "", // Never send password to frontend
		RootTopic:     wr.config.MeshSettings.MqttRoot,
		GatewayTopic:  wr.config.MeshSettings.MqttRoot + "/Gateway",
		Channels:      channels,
	}
}

func (wr *WebRouter) getTemplMqttConfig(r *http.Request, user *models.User) *components.MqttConfigData {
	if user == nil {
		return nil
	}

	channels := make([]components.ChannelInfo, len(wr.config.MeshSettings.Channels))
	for i, ch := range wr.config.MeshSettings.Channels {
		channels[i] = components.ChannelInfo{
			Name:   ch.Name,
			PSK:    ch.Key,
			Export: ch.Export,
		}
	}

	url := r.URL
	url.Host = r.Host
	return &components.MqttConfigData{
		ServerAddress: url.Hostname(),
		Username:      user.UserName,
		Password:      "", // Never send password to frontend
		RootTopic:     wr.config.MeshSettings.MqttRoot,
		GatewayTopic:  wr.config.MeshSettings.MqttRoot + "/Gateway",
		Channels:      channels,
	}
}

type SetPasswordRequest struct {
	Password string `json:"password"`
}

type SetPasswordResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type NodeResponse struct {
	NodeID           string   `json:"node_id"`
	ShortName        string   `json:"short_name"`
	LongName         string   `json:"long_name"`
	NodeColor        string   `json:"node_color,omitempty"`
	ProxyType        string   `json:"proxy_type"`
	Address          string   `json:"address"`
	RootTopic        string   `json:"root_topic"`
	NodeRole         string   `json:"node_role,omitempty"`
	HwModel          string   `json:"hw_model,omitempty"`
	LastSeen         *string  `json:"last_seen,omitempty"`
	IsDownlink       bool     `json:"is_downlink"`
	IsValidGateway   bool     `json:"is_valid_gateway"`
	IsConnected      bool     `json:"is_connected"`
	IsMeshDevice     bool     `json:"is_mesh_device"`
	ClientID         string   `json:"client_id"`
	UserDisplay      string   `json:"user_display,omitempty"`
	ValidationErrors []string `json:"validation_errors,omitempty"`
}

type NodesResponse struct {
	Nodes        []NodeResponse `json:"nodes"`
	OtherClients []NodeResponse `json:"other_clients"`
}

func (wr *WebRouter) setMqttPassword(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req SetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(SetPasswordResponse{
			Success: false,
			Message: "Password cannot be empty",
		})
		return
	}

	// Generate hash and salt
	hash, salt := auth.GenerateHashAndSalt(req.Password)

	// Save to database
	err = wr.storage.Users.SetPassword(user.ID, hash, salt)
	if err != nil {
		slog.Error("error setting user password", "error", err, "user_id", user.ID)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SetPasswordResponse{
		Success: true,
		Message: "Password set successfully",
	})
}

func (wr *WebRouter) getNodes(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse query parameters for filtering
	query := r.URL.Query()
	connectedOnly := query.Get("connected_only") == "true"
	validGatewayOnly := query.Get("valid_gateway_only") == "true"
	allUsers := query.Get("all_users") == "true"

	// Authorization check for all_users flag
	if allUsers && !user.IsSuperuser {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Get clients based on authorization
	var clients []*models.ClientDetails
	if allUsers {
		clients = wr.MqttServer.GetAllClients()
	} else {
		clients = wr.MqttServer.GetUserClients(user.UserName)
	}

	nodes := []NodeResponse{}
	otherClients := []NodeResponse{}

	knownNodes := []uint32{}
	for _, c := range clients {
		// Apply filters for mesh devices
		if connectedOnly && c.Address == "" {
			continue
		}

		ipAddr, _ := c.GetIPAddress()

		userDisplay := ""
		if allUsers {
			userDisplay = wr.getUserDisplay(c.MqttUserName)
		}

		nr := NodeResponse{
			ClientID:     c.ClientID,
			Address:      ipAddr,
			IsConnected:  c.Address != "",
			IsMeshDevice: false,
			UserDisplay:  userDisplay,
		}

		if !c.IsMeshDevice() {
			otherClients = append(otherClients, nr)
			continue
		}

		if validGatewayOnly && !c.IsValidGateway() {
			continue
		}

		nodeID := ""
		nodeRole := ""
		hwModel := ""
		var lastSeen *string

		if c.NodeDetails != nil {
			nodeID = c.NodeDetails.NodeID.String()
			nodeRole = c.NodeDetails.NodeRole
			hwModel = c.NodeDetails.HwModel
			knownNodes = append(knownNodes, uint32(c.NodeDetails.NodeID))

			if c.NodeDetails.LastSeen != nil {
				lastSeenStr := c.NodeDetails.LastSeen.Format("2006-01-02 15:04:05")
				lastSeen = &lastSeenStr
			}
		}

		nr.NodeID = nodeID
		nr.ShortName = c.GetShortName()
		nr.LongName = c.GetLongName()
		nr.ProxyType = c.ProxyType
		nr.RootTopic = c.RootTopic
		nr.NodeRole = nodeRole
		nr.HwModel = hwModel
		nr.LastSeen = lastSeen
		nr.IsDownlink = c.IsDownlinkVerified()
		nr.IsValidGateway = c.IsValidGateway()
		nr.IsMeshDevice = true
		nr.ClientID = c.ClientID
		nr.ValidationErrors = c.GetValidationErrors()

		// Add node color if node details are available
		if c.NodeDetails != nil {
			nr.NodeColor = c.NodeDetails.GetNodeColor()
		}

		nodes = append(nodes, nr)
	}

	// Include offline nodes if not filtering for connected only
	if !connectedOnly {
		var offlineNodes []*models.NodeInfo
		var err error
		if allUsers {
			offlineNodes, err = wr.storage.NodeDB.GetAllExceptNodeIDs(knownNodes)
		} else {
			offlineNodes, err = wr.storage.NodeDB.GetByUserIDExceptNodeIDs(user.ID, knownNodes)
		}

		if err == nil {
			for _, n := range offlineNodes {
				var lastSeen *string
				if n.LastSeen != nil {
					lastSeenStr := n.LastSeen.Format("2006-01-02 15:04:05")
					lastSeen = &lastSeenStr
				}

				nodes = append(nodes, NodeResponse{
					NodeID:         n.NodeID.String(),
					ShortName:      n.GetSafeShortName(),
					LongName:       n.GetSafeLongName(),
					NodeColor:      n.GetNodeColor(),
					NodeRole:       n.NodeRole,
					HwModel:        n.HwModel,
					LastSeen:       lastSeen,
					IsConnected:    false,
					IsMeshDevice:   true,
					IsValidGateway: false,
					ValidationErrors: []string{
						"Node is offline",
					},
				})
			}
		}
	}

	// Sort nodes by NodeID
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].NodeID == "" && nodes[j].NodeID != "" {
			return true
		}
		if nodes[i].NodeID != "" && nodes[j].NodeID == "" {
			return false
		}
		if nodes[i].NodeID != "" && nodes[j].NodeID != "" {
			return nodes[i].NodeID < nodes[j].NodeID
		}
		return nodes[i].ClientID < nodes[j].ClientID
	})

	// Sort other clients by ClientID
	sort.Slice(otherClients, func(i, j int) bool {
		return otherClients[i].ClientID < otherClients[j].ClientID
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(NodesResponse{
		Nodes:        nodes,
		OtherClients: otherClients,
	})
}

func (wr *WebRouter) usersPage(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !user.IsSuperuser {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	pageData := components.UsersPageData{
		IsSuperuser: true,
	}

	if err := components.UsersPage(pageData).Render(r.Context(), w); err != nil {
		slog.Error("error rendering users page", "error", err)
		http.Error(w, "Error rendering page", http.StatusInternalServerError)
	}
}

type UserResponse struct {
	ID               int     `json:"id"`
	DisplayName      *string `json:"display_name"`
	DiscordID        *int64  `json:"discord_id"`
	UserName         string  `json:"username"`
	IsSuperuser      bool    `json:"is_superuser"`
	IsGatewayAllowed bool    `json:"is_gateway_allowed"`
	Created          string  `json:"created"`
}

type UsersResponse struct {
	Users []UserResponse `json:"users"`
}

func (wr *WebRouter) getUsers(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !user.IsSuperuser {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	users, err := wr.storage.Users.GetAll()
	if err != nil {
		slog.Error("error fetching users", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	userResponses := make([]UserResponse, len(users))
	for i, u := range users {
		userResponses[i] = UserResponse{
			ID:               u.ID,
			DisplayName:      u.DisplayName,
			DiscordID:        u.DiscordID,
			UserName:         u.UserName,
			IsSuperuser:      u.IsSuperuser,
			IsGatewayAllowed: u.IsGatewayAllowed,
			Created:          u.Created.Format("2006-01-02 15:04:05"),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UsersResponse{Users: userResponses})
}

type UpdateUserRequest struct {
	DisplayName      *string `json:"display_name"`
	UserName         string  `json:"username"`
	IsSuperuser      bool    `json:"is_superuser"`
	IsGatewayAllowed bool    `json:"is_gateway_allowed"`
}

func (wr *WebRouter) updateUser(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !user.IsSuperuser {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	userID := vars["id"]
	if userID == "" {
		http.Error(w, "User ID required", http.StatusBadRequest)
		return
	}

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Convert string ID to int
	var id int
	if _, err := fmt.Sscanf(userID, "%d", &id); err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Fetch existing user
	existingUser, err := wr.storage.Users.GetByID(id)
	if err != nil || existingUser == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Update fields
	existingUser.DisplayName = req.DisplayName
	existingUser.UserName = req.UserName
	existingUser.IsSuperuser = req.IsSuperuser
	existingUser.IsGatewayAllowed = req.IsGatewayAllowed

	err = wr.storage.Users.UpdateUser(existingUser)
	if err != nil {
		slog.Error("error updating user", "error", err, "user_id", id)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "User updated successfully",
	})
}

func (wr *WebRouter) deleteUser(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !user.IsSuperuser {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	userID := vars["id"]
	if userID == "" {
		http.Error(w, "User ID required", http.StatusBadRequest)
		return
	}

	// Convert string ID to int
	var id int
	if _, err := fmt.Sscanf(userID, "%d", &id); err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Prevent self-deletion
	if id == user.ID {
		http.Error(w, "Cannot delete your own account", http.StatusBadRequest)
		return
	}

	err = wr.storage.Users.DeleteUser(id)
	if err != nil {
		slog.Error("error deleting user", "error", err, "user_id", id)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "User deleted successfully",
	})
}

// ForwardingStatusResponse is the API response for forwarding status
type ForwardingStatusResponse struct {
	Enabled bool                     `json:"enabled"`
	Targets []hooks.ForwardingStatus `json:"targets"`
}

// getForwardingStatusData returns forwarding status data for template rendering
func (wr *WebRouter) getForwardingStatusData() *components.ForwardingStatusData {
	if wr.ForwardingHook == nil || !wr.ForwardingHook.IsEnabled() {
		return nil
	}

	statuses := wr.ForwardingHook.GetStatus()
	targets := make([]components.ForwardingTargetData, len(statuses))

	for i, s := range statuses {
		target := components.ForwardingTargetData{
			Name:      s.Name,
			Address:   s.Address,
			Connected: s.Connected,
			LastError: s.LastError,
			Topics:    s.Topics,
		}
		if s.ConnectedAt != nil {
			target.ConnectedAt = s.ConnectedAt.Format("2006-01-02 15:04:05")
		}
		if s.LastErrorTime != nil {
			target.LastErrorTime = s.LastErrorTime.Format("2006-01-02 15:04:05")
		}
		targets[i] = target
	}

	return &components.ForwardingStatusData{
		Enabled: true,
		Targets: targets,
	}
}

func (wr *WebRouter) getForwardingStatus(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !user.IsSuperuser {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	response := ForwardingStatusResponse{
		Enabled: false,
		Targets: []hooks.ForwardingStatus{},
	}

	if wr.ForwardingHook != nil && wr.ForwardingHook.IsEnabled() {
		response.Enabled = true
		response.Targets = wr.ForwardingHook.GetStatus()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
