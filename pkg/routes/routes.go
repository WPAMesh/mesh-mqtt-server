package routes

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/kabili207/mesh-mqtt-server/internal/web"
	"github.com/kabili207/mesh-mqtt-server/pkg/auth"
	"github.com/kabili207/mesh-mqtt-server/pkg/config"
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
	config       config.Configuration
	storage      store.Stores
	sessionStore *sessions.CookieStore
	MqttServer   models.MeshMqttServer
	// the name of the session cookie. Should be adjusted as appropriate

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
	Name     string
	PSK      string
	IsCustom bool
}

type PageVariables struct {
	PageTitle      string
	Alerts         []Alert
	ConnectedNodes []*models.ClientDetails
	OtherClients   []*models.ClientDetails
	MqttConfig     *MqttConfigData
	ShowOnboarding bool
}

func (wr *WebRouter) handleRequests(listenAddr string) error {
	// creates a new instance of a mux router
	myRouter := mux.NewRouter().StrictSlash(true)

	//staticFS, _ := fs.Sub(web.ContentFS, "static")

	myRouter.HandleFunc("/", wr.homePage)
	myRouter.HandleFunc("/all-nodes", wr.allNodes)
	myRouter.HandleFunc("/login", wr.loginPage)
	myRouter.HandleFunc("/api/set-mqtt-password", wr.setMqttPassword).Methods("POST")
	myRouter.HandleFunc("/auth/logout", wr.userLogoutHandler)
	myRouter.HandleFunc("/auth/discord/login", wr.discordLoginHandler)
	myRouter.HandleFunc("/auth/discord/callback", wr.discordCallbackHandler)
	myRouter.PathPrefix("/static").Handler(http.FileServerFS(web.ContentFS))

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

	tmpl, err := web.GetHTMLTemplate("login")
	if err != nil {
		slog.Error("error loading login template", "error", err)
	}

	err = tmpl.ExecuteTemplate(w, "base", nil) /*PageVariables{
		PageTitle: "Incoming Packages",
		Data:      web.ShipmentFromTrackhiveList(incoming),
		Carriers:  couriers,
		Alerts:    alerts,
	}*/
	if err != nil {
		slog.Error("error executing login template", "error", err)
		http.Error(w, "Error parsing template", 500)
	}
}

func (wr *WebRouter) homePage(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
	} else {

		clients := wr.MqttServer.GetUserClients(user.UserName)

		nodes := []*models.ClientDetails{}
		otherClients := []*models.ClientDetails{}

		knownNodes := []uint32{}
		for _, c := range clients {
			if c.IsMeshDevice() {
				nodes = append(nodes, c)
				if c.NodeDetails != nil {
					knownNodes = append(knownNodes, uint32(c.NodeDetails.NodeID))
				}
			} else {
				otherClients = append(otherClients, c)
			}
		}
		offlineNodes, err := wr.storage.NodeDB.GetByUserIDExceptNodeIDs(user.ID, knownNodes)
		for _, n := range offlineNodes {
			nodes = append(nodes, &models.ClientDetails{
				NodeDetails: n,
			})
		}

		sort.Slice(otherClients, func(i, j int) bool {
			return otherClients[i].ClientID < otherClients[j].ClientID
		})

		sort.Slice(nodes, func(i, j int) bool {
			ni, nj := nodes[i], nodes[j]
			if ni.NodeDetails == nil && nj.NodeDetails != nil {
				return true
			}
			if ni.NodeDetails != nil && nj.NodeDetails == nil {
				return false
			}
			if ni.NodeDetails != nil && nj.NodeDetails != nil {
				return ni.NodeDetails.NodeID < nj.NodeDetails.NodeID
			}
			return ni.ClientID < nj.ClientID
		})

		tmpl, err := web.GetHTMLTemplate("my_nodes")
		if err != nil {
			slog.Error("error loading my_nodes template", "error", err)
		}

		mqttConfig := wr.getMqttConfig(user)
		showOnboarding := user.PasswordHash == "" // Show onboarding if no password set

		err = tmpl.ExecuteTemplate(w, "base", PageVariables{
			ConnectedNodes: nodes,
			OtherClients:   otherClients,
			Alerts:         nil,
			MqttConfig:     mqttConfig,
			ShowOnboarding: showOnboarding,
		})
		if err != nil {
			slog.Error("error executing my_nodes template", "error", err)
			http.Error(w, "Error parsing template", 500)
		}
	}
}

func (wr *WebRouter) allNodes(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
	} else if !user.IsSuperuser {
		http.Redirect(w, r, "/", http.StatusFound)
	} else {

		clients := wr.MqttServer.GetAllClients()

		nodes := []*models.ClientDetails{}
		otherClients := []*models.ClientDetails{}

		knownNodes := []uint32{}
		for _, c := range clients {
			if c.IsMeshDevice() {
				nodes = append(nodes, c)
				if c.NodeDetails != nil {
					knownNodes = append(knownNodes, uint32(c.NodeDetails.NodeID))
				}
			} else {
				otherClients = append(otherClients, c)
			}
		}
		// TODO: Add a filter parameter to optionally include offline nodes
		//offlineNodes, err := wr.storage.NodeDB.GetAllExceptNodeIDs(knownNodes)
		//for _, n := range offlineNodes {
		//	nodes = append(nodes, &models.ClientDetails{
		//		NodeDetails: n,
		//	})
		//}

		sort.Slice(otherClients, func(i, j int) bool {
			return otherClients[i].ClientID < otherClients[j].ClientID
		})

		sort.Slice(nodes, func(i, j int) bool {
			ni, nj := nodes[i], nodes[j]
			if ni.NodeDetails == nil && nj.NodeDetails != nil {
				return true
			}
			if ni.NodeDetails != nil && nj.NodeDetails == nil {
				return false
			}
			if ni.NodeDetails != nil && nj.NodeDetails != nil {
				return ni.NodeDetails.NodeID < nj.NodeDetails.NodeID
			}
			return ni.ClientID < nj.ClientID
		})

		tmpl, err := web.GetHTMLTemplate("all_nodes")
		if err != nil {
			slog.Error("error loading all_nodes template", "error", err)
		}

		err = tmpl.ExecuteTemplate(w, "base", PageVariables{
			ConnectedNodes: nodes,
			OtherClients:   otherClients,
			Alerts:         nil,
		})
		if err != nil {
			slog.Error("error executing all_nodes template", "error", err)
			http.Error(w, "Error parsing template", 500)
		}
	}
}

func (wr *WebRouter) getMqttConfig(user *models.User) *MqttConfigData {
	if user == nil {
		return nil
	}

	channels := make([]ChannelInfo, len(wr.config.MeshSettings.Channels))
	for i, ch := range wr.config.MeshSettings.Channels {
		channels[i] = ChannelInfo{
			Name:     ch.Name,
			PSK:      ch.Key,
			IsCustom: false,
		}
	}

	// Determine if user needs to set password (empty hash means no password set)
	hasPassword := user.PasswordHash != ""

	return &MqttConfigData{
		ServerAddress: wr.config.BaseURL,
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
