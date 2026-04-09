package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

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
	mccodec "github.com/kabili207/meshcore-go/core/codec"
	meshtastic "github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"golang.org/x/oauth2"
)

const (
	sessionName = "mesht_mqtt"
)

// convertOkToMqttStats converts model stats to the display format
func convertOkToMqttStats(stats *models.OkToMqttStats) *components.OkToMqttStatsData {
	if stats == nil || stats.ByPortNum == nil || len(stats.ByPortNum) == 0 {
		return nil
	}

	totalWith, totalWithout := stats.GetTotals()
	result := &components.OkToMqttStatsData{
		TotalWithFlag:    totalWith,
		TotalWithoutFlag: totalWithout,
		ByPortNum:        make([]components.PortNumStatsData, 0, len(stats.ByPortNum)),
	}

	for portNum, portStats := range stats.ByPortNum {
		result.ByPortNum = append(result.ByPortNum, components.PortNumStatsData{
			PortNum:     portNum,
			PortName:    pb.PortNum(portNum).String(),
			WithFlag:    portStats.WithFlag,
			WithoutFlag: portStats.WithoutFlag,
		})
	}

	// Sort by port number for consistent display
	sort.Slice(result.ByPortNum, func(i, j int) bool {
		return result.ByPortNum[i].PortNum < result.ByPortNum[j].PortNum
	})

	return result
}

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
	myRouter.HandleFunc("/api/gateway-stats", wr.getGatewayStats).Methods("GET")
	myRouter.HandleFunc("/blocked-nodes", wr.blockedNodesPage)
	myRouter.HandleFunc("/api/blocked-nodes-html", wr.blockedNodesHTML).Methods("GET")
	myRouter.HandleFunc("/api/map-data", wr.getMapData).Methods("GET")
	myRouter.HandleFunc("/api/blocked-nodes", wr.getBlockedNodes).Methods("GET")
	myRouter.HandleFunc("/api/blocked-nodes", wr.blockNode).Methods("POST")
	myRouter.HandleFunc("/api/blocked-nodes/{nodeId}", wr.unblockNode).Methods("DELETE")
	myRouter.HandleFunc("/map", wr.mapPage)
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

	nodes, meshcoreClients, otherClients := wr.getNodesData(user, false, true, false)

	mqttConfig := wr.getTemplMqttConfig(r, user)
	showOnboarding := user.PasswordHash == "" // Show onboarding if no password set

	pageData := components.MyNodesPageData{
		Nodes:           nodes,
		MeshCoreClients: meshcoreClients,
		OtherClients:    otherClients,
		MqttConfig:      mqttConfig,
		ShowOnboarding:  showOnboarding,
		IsSuperuser:     user.IsSuperuser,
		IsAdmin:         user.IsAdminOrAbove(),
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
	if !user.IsAdminOrAbove() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	nodes, meshcoreClients, otherClients := wr.getNodesData(user, true, true, false)

	// Only superusers can see forwarding status
	var forwardingStatus *components.ForwardingStatusData
	if user.IsSuperuser {
		forwardingStatus = wr.getForwardingStatusData()
	}

	pageData := components.AllNodesPageData{
		Nodes:            nodes,
		MeshCoreClients:  meshcoreClients,
		OtherClients:     otherClients,
		IsSuperuser:      user.IsSuperuser,
		IsAdmin:          user.IsAdminOrAbove(),
		ForwardingStatus: forwardingStatus,
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

func (wr *WebRouter) getUserDisplayByID(userID int) string {
	user, err := wr.storage.Users.GetByID(userID)
	if err != nil || user == nil {
		return ""
	}
	if user.DisplayName != nil && *user.DisplayName != "" {
		return *user.DisplayName
	}
	return user.UserName
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

type NodesResponse struct {
	Nodes           []components.NodeData           `json:"nodes"`
	MeshCoreClients []components.MeshCoreClientData `json:"meshcore_clients"`
	OtherClients    []components.OtherClientData    `json:"other_clients"`
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
	if allUsers && !user.IsAdminOrAbove() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	nodes, meshcoreClients, otherClients := wr.getNodesData(user, allUsers, connectedOnly, validGatewayOnly)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(NodesResponse{
		Nodes:           nodes,
		MeshCoreClients: meshcoreClients,
		OtherClients:    otherClients,
	})
}

func (wr *WebRouter) usersPage(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !user.IsAdminOrAbove() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	pageData := components.UsersPageData{
		IsSuperuser: user.IsSuperuser,
		IsAdmin:     user.IsAdminOrAbove(),
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
	IsAdmin          bool    `json:"is_admin"`
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
	if !user.IsAdminOrAbove() {
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
			IsAdmin:          u.IsAdmin,
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
	IsGatewayAllowed bool    `json:"is_gateway_allowed"`
}

func (wr *WebRouter) updateUser(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !user.IsAdminOrAbove() {
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

	// Admins cannot edit superusers
	if !user.IsSuperuser && existingUser.IsSuperuser {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Update fields (IsSuperuser intentionally not editable via API)
	existingUser.DisplayName = req.DisplayName
	existingUser.UserName = req.UserName
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
	if !user.IsAdminOrAbove() {
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

	// Admins cannot delete superusers
	if !user.IsSuperuser {
		targetUser, err := wr.storage.Users.GetByID(id)
		if err != nil || targetUser == nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		if targetUser.IsSuperuser {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
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

// GatewayStatsEntry holds stats for a single gateway
type GatewayStatsEntry struct {
	NodeID        string                        `json:"node_id"`
	ShortName     string                        `json:"short_name"`
	LongName      string                        `json:"long_name"`
	ClientID      string                        `json:"client_id"`
	UserDisplay   string                        `json:"user_display,omitempty"`
	OkToMqttStats *components.OkToMqttStatsData `json:"ok_to_mqtt_stats"`
}

// GatewayStatsResponse is the API response for gateway stats
type GatewayStatsResponse struct {
	Gateways []GatewayStatsEntry `json:"gateways"`
}

func (wr *WebRouter) getGatewayStats(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	query := r.URL.Query()
	allUsers := query.Get("all_users") == "true"

	// Authorization check for all_users flag
	if allUsers && !user.IsAdminOrAbove() {
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

	gateways := []GatewayStatsEntry{}

	for _, c := range clients {
		// Only include mesh devices with stats
		if !c.IsMeshDevice() {
			continue
		}

		stats := convertOkToMqttStats(&c.OkToMqttStats)
		if stats == nil {
			continue
		}

		nodeID := ""
		if c.NodeDetails != nil {
			nodeID = c.NodeDetails.NodeID.String()
		}

		userDisplay := ""
		if allUsers {
			userDisplay = wr.getUserDisplay(c.MqttUserName)
		}

		gateways = append(gateways, GatewayStatsEntry{
			NodeID:        nodeID,
			ShortName:     c.GetShortName(),
			LongName:      c.GetLongName(),
			ClientID:      c.ClientID,
			UserDisplay:   userDisplay,
			OkToMqttStats: stats,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(GatewayStatsResponse{
		Gateways: gateways,
	})
}

// truncatePosition applies precision-based fuzzing to coordinates, matching
// the Meshtastic firmware's computeImpreciseLatLon algorithm. It masks the
// low-order bits of the integer coordinate and centers the result within the
// quantization cell. precisionBits controls accuracy: 14 ≈ 1.5km, 16 ≈ 364m.
func truncatePosition(lat, lon float64, precisionBits uint8) (float64, float64) {
	if precisionBits == 0 || precisionBits >= 32 {
		return lat, lon
	}
	latI := int32(lat * 1e7)
	lonI := int32(lon * 1e7)

	mask := uint32(0xFFFFFFFF) << (32 - precisionBits)
	centerOffset := uint32(1) << (31 - precisionBits)

	latU := (uint32(latI) & mask) + centerOffset
	lonU := (uint32(lonI) & mask) + centerOffset

	return float64(int32(latU)) * 1e-7, float64(int32(lonU)) * 1e-7
}

// MapNodeData is a lightweight node representation for the map endpoint
type MapNodeData struct {
	NodeID         string  `json:"node_id"`
	ShortName      string  `json:"short_name"`
	LongName       string  `json:"long_name"`
	NodeColor      string  `json:"node_color"`
	Latitude       float64 `json:"latitude"`
	Longitude      float64 `json:"longitude"`
	IsValidGateway bool    `json:"is_valid_gateway"`
	IsConnected    bool    `json:"is_connected"`
	NodeRole       string  `json:"node_role,omitempty"`
	Source         string  `json:"source"`
	UserDisplay    string  `json:"user_display,omitempty"`
}

func (wr *WebRouter) getMapData(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !user.IsAdminOrAbove() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	nodes, _, _ := wr.getNodesData(user, true, false, false)

	mapNodes := []MapNodeData{}

	cutoffDate := time.Now().Add(time.Hour * -24)

	// Meshtastic nodes with location
	for _, n := range nodes {
		if n.Latitude == nil || n.Longitude == nil || n.LastSeen == nil {
			continue
		}
		lastSeen, err := time.ParseInLocation("2006-01-02 15:04:05", *n.LastSeen, time.UTC)
		if err != nil || cutoffDate.After(lastSeen) {
			continue
		}
		mapNodes = append(mapNodes, MapNodeData{
			NodeID:         n.NodeID,
			ShortName:      n.ShortName,
			LongName:       n.LongName,
			NodeColor:      n.NodeColor,
			Latitude:       *n.Latitude,
			Longitude:      *n.Longitude,
			IsValidGateway: n.IsValidGateway,
			IsConnected:    n.IsConnected,
			NodeRole:       n.NodeRole,
			Source:         "meshtastic",
			UserDisplay:    n.UserDisplay,
		})
	}

	// Build set of connected MeshCore pubkeys from active MeshCore clients
	connectedMCKeys := make(map[string]bool)
	for _, c := range wr.MqttServer.GetAllClients() {
		if c.IsMeshCoreClient {
			c.RLock()
			for k := range c.DirectMCNodes {
				connectedMCKeys[k] = true
			}
			c.RUnlock()
		}
	}

	// MeshCore direct-connect (gateway) nodes with location
	mcNodes, err := wr.storage.MeshCoreNodes.GetAllNodes()
	if err == nil {
		for _, mc := range mcNodes {
			if !mc.IsDirect || !mc.HasLocation() {
				continue
			}

			if mc.LastSeen == nil || cutoffDate.After(*mc.LastSeen) {
				continue
			}

			fullHex := strings.ToUpper(mc.GetMeshCoreID().String())
			nodeID := fullHex[:8] + "..." + fullHex[len(fullHex)-8:]
			lat, lon := *mc.Latitude, *mc.Longitude
			lat, lon = truncatePosition(lat, lon, 14)
			pubKeyHex := hex.EncodeToString(mc.PubKey)
			var userDisplay string
			if mc.UserID != nil {
				userDisplay = wr.getUserDisplayByID(*mc.UserID)
			}
			mapNodes = append(mapNodes, MapNodeData{
				NodeID:         nodeID,
				ShortName:      mc.Name,
				LongName:       mc.Name,
				NodeColor:      "#6c757d",
				Latitude:       lat,
				Longitude:      lon,
				IsValidGateway: true,
				IsConnected:    connectedMCKeys[pubKeyHex],
				NodeRole:       mccodec.NodeTypeName(uint8(mc.NodeType)),
				Source:         "meshcore",
				UserDisplay:    userDisplay,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mapNodes)
}

func (wr *WebRouter) mapPage(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !user.IsAdminOrAbove() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	pageData := components.MapPageData{
		IsSuperuser: user.IsSuperuser,
		IsAdmin:     user.IsAdminOrAbove(),
	}

	if err := components.MapPage(pageData).Render(r.Context(), w); err != nil {
		slog.Error("error rendering map page", "error", err)
		http.Error(w, "Error rendering page", http.StatusInternalServerError)
	}
}

func (wr *WebRouter) blockedNodesPage(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !user.IsAdminOrAbove() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	pageData := components.BlockedNodesPageData{
		IsSuperuser: user.IsSuperuser,
		IsAdmin:     user.IsAdminOrAbove(),
	}

	if err := components.BlockedNodesPage(pageData).Render(r.Context(), w); err != nil {
		slog.Error("error rendering blocked nodes page", "error", err)
		http.Error(w, "Error rendering page", http.StatusInternalServerError)
	}
}

func (wr *WebRouter) blockedNodesHTML(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !user.IsAdminOrAbove() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	blocked, err := wr.storage.BlockedNodes.GetAll()
	if err != nil {
		slog.Error("error fetching blocked nodes", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	rows := make([]components.BlockedNodeRowData, len(blocked))
	for i, b := range blocked {
		nodeID := meshtastic.NodeID(b.NodeID)
		row := components.BlockedNodeRowData{
			NodeID:    nodeID.String(),
			NodeColor: nodeID.GetNodeColor(),
			Reason:    b.Reason,
			BlockedAt: b.BlockedAt.Format("2006-01-02 15:04:05"),
		}

		// Look up node info if this node has been seen before
		if nodeInfo, err := wr.storage.NodeDB.GetNode(b.NodeID); err == nil && nodeInfo != nil {
			row.LongName = nodeInfo.LongName
			row.ShortName = nodeInfo.ShortName
		}

		// Look up who blocked this node
		if b.BlockedBy != nil {
			if blocker, err := wr.storage.Users.GetByID(*b.BlockedBy); err == nil && blocker != nil {
				if blocker.DisplayName != nil && *blocker.DisplayName != "" {
					row.BlockedBy = *blocker.DisplayName
				} else {
					row.BlockedBy = blocker.UserName
				}
			}
		}

		rows[i] = row
	}

	w.Header().Set("Content-Type", "text/html")
	if err := components.BlockedNodesTableContent(rows).Render(r.Context(), w); err != nil {
		slog.Error("error rendering blocked nodes HTML", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (wr *WebRouter) getBlockedNodes(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !user.IsAdminOrAbove() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	nodes, err := wr.storage.BlockedNodes.GetAll()
	if err != nil {
		slog.Error("error fetching blocked nodes", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nodes)
}

type BlockNodeRequest struct {
	NodeID string `json:"node_id"`
	Reason string `json:"reason"`
}

func (wr *WebRouter) blockNode(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !user.IsAdminOrAbove() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req BlockNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	nodeID, err := meshtastic.ParseNodeID(req.NodeID)
	if err != nil {
		http.Error(w, "Invalid node ID", http.StatusBadRequest)
		return
	}

	err = wr.storage.BlockedNodes.Block(uint32(nodeID), req.Reason, &user.ID)
	if err != nil {
		slog.Error("error blocking node", "error", err, "node_id", req.NodeID)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	slog.Info("node blocked", "node_id", nodeID, "reason", req.Reason, "blocked_by", user.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Node blocked successfully",
	})
}

func (wr *WebRouter) unblockNode(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !user.IsAdminOrAbove() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	nodeIDStr := vars["nodeId"]
	if nodeIDStr == "" {
		http.Error(w, "Node ID required", http.StatusBadRequest)
		return
	}

	nodeID, err := meshtastic.ParseNodeID(nodeIDStr)
	if err != nil {
		http.Error(w, "Invalid node ID", http.StatusBadRequest)
		return
	}

	err = wr.storage.BlockedNodes.Unblock(uint32(nodeID))
	if err != nil {
		slog.Error("error unblocking node", "error", err, "node_id", nodeIDStr)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	slog.Info("node unblocked", "node_id", nodeID, "unblocked_by", user.ID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Node unblocked successfully",
	})
}
