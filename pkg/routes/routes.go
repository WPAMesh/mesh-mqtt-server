package routes

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/kabili207/mesh-mqtt-server/internal/web"
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

type PageVariables struct {
	PageTitle      string
	Alerts         []Alert
	ConnectedNodes []*models.ClientDetails
	OtherClients   []*models.ClientDetails
}

func (wr *WebRouter) handleRequests(listenAddr string) error {
	// creates a new instance of a mux router
	myRouter := mux.NewRouter().StrictSlash(true)

	//staticFS, _ := fs.Sub(web.ContentFS, "static")

	myRouter.HandleFunc("/", wr.homePage)
	myRouter.HandleFunc("/login", wr.loginPage)
	myRouter.HandleFunc("/auth/logout", wr.userLogoutHandler)
	myRouter.HandleFunc("/auth/discord/login", wr.discordLoginHandler)
	myRouter.HandleFunc("/auth/discord/callback", wr.discordCallbackHandler)
	myRouter.PathPrefix("/static").Handler(http.FileServerFS(web.ContentFS))

	return http.ListenAndServe(listenAddr, myRouter)
}

func (wr *WebRouter) loginPage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := web.GetHTMLTemplate("login")
	if err != nil {
		log.Printf("%q\n", err)
	}

	err = tmpl.ExecuteTemplate(w, "base", nil) /*PageVariables{
		PageTitle: "Incoming Packages",
		Data:      web.ShipmentFromTrackhiveList(incoming),
		Carriers:  couriers,
		Alerts:    alerts,
	}*/
	if err != nil {
		log.Println("Template error")
		log.Println(err)
		http.Error(w, "Error parsing template", 500)
	}
}

func (wr *WebRouter) homePage(w http.ResponseWriter, r *http.Request) {
	log.Println("Endpoint Hit: homePage")
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		//fmt.Fprintln(w, "<a href='/auth/discord/login'>Log in with Discord</a>")
	} else {
		clients := wr.MqttServer.GetUserClients(user.UserName)

		nodes := []*models.ClientDetails{}
		otherClients := []*models.ClientDetails{}

		for _, c := range clients {
			if c.IsMeshDevice() {
				nodes = append(nodes, c)
			} else {
				otherClients = append(otherClients, c)
			}
		}
		tmpl, err := web.GetHTMLTemplate("my_nodes")
		if err != nil {
			log.Printf("%q\n", err)
		}

		err = tmpl.ExecuteTemplate(w, "base", PageVariables{
			ConnectedNodes: nodes,
			OtherClients:   otherClients,
			Alerts:         nil,
		})
		if err != nil {
			log.Println("Template error")
			log.Println(err)
			http.Error(w, "Error parsing template", 500)
		}
	}
}
