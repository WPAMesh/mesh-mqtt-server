package hooks

import (
	"bytes"
	"sync"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/hooks/auth"
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/kabili207/mesh-mqtt-server/pkg/models"
	"github.com/kabili207/mesh-mqtt-server/pkg/store"
	meshtastic "github.com/kabili207/meshtastic-go/core"
)

// sysFilter matches $SYS/# topics for superuser-only access.
var sysFilter auth.RString = `$SYS/#`

// ClientEnricher classifies clients during authentication.
// Called after credential validation succeeds. Implementations can
// modify the ClientDetails in place to set protocol-specific fields.
type ClientEnricher interface {
	// EnrichClient is called during OnConnectAuthenticate after credentials
	// are validated. Returns true if this enricher claimed the client
	// (client ID matched a known pattern). The first enricher to claim
	// stops iteration.
	EnrichClient(cd *models.ClientDetails, cl *mqtt.Client, user *models.User) (claimed bool)
}

// ACLChecker handles protocol-specific ACL decisions.
type ACLChecker interface {
	// CheckACL determines whether the given client is allowed to access
	// the topic. Returns (handled, allowed). If handled is false, the
	// next checker in the chain is tried.
	CheckACL(cd *models.ClientDetails, topic string, write bool) (handled bool, allowed bool)
}

// ClientLifecycleListener receives notifications after connect/disconnect.
type ClientLifecycleListener interface {
	// OnClientAuthenticated is called after a client is successfully
	// authenticated and stored.
	OnClientAuthenticated(cd *models.ClientDetails)
	// OnClientDisconnected is called after a client has been removed.
	OnClientDisconnected(cd *models.ClientDetails)
}

// AuthHookOptions contains configuration for the AuthHook.
type AuthHookOptions struct {
	Server         *mqtt.Server
	Storage        *store.Stores
	ClientNotifier ClientChangeNotifier
}

var _ models.MeshMqttServer = (*AuthHook)(nil)

// AuthHook handles authentication, client lifecycle, and ACL decisions.
// Protocol-specific behavior is delegated to registered enrichers,
// ACL checkers, and lifecycle listeners.
type AuthHook struct {
	mqtt.HookBase
	config       *AuthHookOptions
	knownClients map[string]*models.ClientDetails
	clientLock   sync.RWMutex

	aclCheckers []ACLChecker
	enrichers   []ClientEnricher
	listeners   []ClientLifecycleListener
}

// ID returns the unique identifier for this hook.
func (h *AuthHook) ID() string {
	return "auth-hook"
}

// Provides indicates which MQTT events this hook handles.
func (h *AuthHook) Provides(b byte) bool {
	return bytes.Contains([]byte{
		mqtt.OnConnectAuthenticate,
		mqtt.OnACLCheck,
		mqtt.OnDisconnect,
	}, []byte{b})
}

// Init initializes the AuthHook with the provided configuration.
func (h *AuthHook) Init(config any) error {
	h.Log.Info("initializing auth hook")

	if _, ok := config.(*AuthHookOptions); !ok && config != nil {
		return mqtt.ErrInvalidConfigType
	}

	h.config = config.(*AuthHookOptions)
	if h.config.Server == nil || h.config.Storage == nil {
		return mqtt.ErrInvalidConfigType
	}

	h.knownClients = make(map[string]*models.ClientDetails)
	return nil
}

// Stop gracefully shuts down the auth hook.
func (h *AuthHook) Stop() error {
	h.Log.Info("stopping auth hook")
	return nil
}

// RegisterClientEnricher adds an enricher that classifies clients during authentication.
func (h *AuthHook) RegisterClientEnricher(e ClientEnricher) {
	h.enrichers = append(h.enrichers, e)
}

// RegisterACLChecker adds a checker for protocol-specific ACL decisions.
func (h *AuthHook) RegisterACLChecker(c ACLChecker) {
	h.aclCheckers = append(h.aclCheckers, c)
}

// RegisterLifecycleListener adds a listener for client connect/disconnect events.
func (h *AuthHook) RegisterLifecycleListener(l ClientLifecycleListener) {
	h.listeners = append(h.listeners, l)
}

// OnConnectAuthenticate validates credentials, runs enrichers, and stores the client.
func (h *AuthHook) OnConnectAuthenticate(cl *mqtt.Client, pk packets.Packet) bool {
	user := string(pk.Connect.Username)
	pass := pk.Connect.Password
	clientID := cl.ID

	validatedUser := h.validateUser(user, string(pass))
	if validatedUser == nil {
		h.Log.Warn("authentication failed", "username", user, "remote_addr", cl.Net.Remote)
		return false
	}

	cd := &models.ClientDetails{
		MqttUserName:       user,
		ClientID:           clientID,
		UserID:             validatedUser.ID,
		Address:            cl.Net.Remote,
		ConnectedAt:        time.Now(),
		OkToMqttViolations: models.NewOkToMqttWindow(10 * time.Minute),
	}

	// Let enrichers classify and populate protocol-specific fields
	for _, enricher := range h.enrichers {
		if enricher.EnrichClient(cd, cl, validatedUser) {
			break
		}
	}

	h.clientLock.Lock()
	h.knownClients[clientID] = cd
	h.clientLock.Unlock()

	h.Log.Info("client authenticated",
		"username", user,
		"client", clientID,
		"display", cd.GetDisplayName())

	// Notify lifecycle listeners asynchronously
	for _, listener := range h.listeners {
		go listener.OnClientAuthenticated(cd)
	}

	go h.NotifyClientChange()

	return true
}

// OnACLCheck handles generic ACL concerns and delegates to registered checkers.
func (h *AuthHook) OnACLCheck(cl *mqtt.Client, topic string, write bool) bool {
	h.clientLock.RLock()
	cd, ok := h.knownClients[cl.ID]
	h.clientLock.RUnlock()

	if !ok {
		h.Log.Warn("unknown client in ACL check",
			"client", cl.ID,
			"username", string(cl.Properties.Username),
			"topic", topic)
		return false
	}

	// $SYS topics: superuser only
	if sysFilter.FilterMatches(topic) {
		isSU, err := h.config.Storage.Users.IsSuperuser(cd.UserID)
		if err != nil {
			h.Log.Warn("error checking superuser status", "user_id", cd.UserID, "error", err)
			return false
		}
		if !isSU {
			h.Log.Warn("ACL denied: non-superuser accessing $SYS topic",
				"client", cl.ID,
				"user", cd.MqttUserName,
				"topic", topic)
		}
		return isSU
	}

	// Delegate to registered ACL checkers
	for _, checker := range h.aclCheckers {
		handled, allowed := checker.CheckACL(cd, topic, write)
		if handled {
			return allowed
		}
	}

	// No checker claimed this client/topic combination
	h.Log.Warn("no ACL checker handled request",
		"client", cl.ID,
		"topic", topic)
	return false
}

// OnDisconnect removes the client and notifies listeners.
func (h *AuthHook) OnDisconnect(cl *mqtt.Client, err error, expire bool) {
	h.clientLock.Lock()
	cd, ok := h.knownClients[cl.ID]
	deleted := false
	if ok && cd.Address == cl.Net.Remote {
		delete(h.knownClients, cl.ID)
		deleted = true
	}
	h.clientLock.Unlock()

	if err != nil {
		h.Log.Info("client disconnected", "client", cl.ID, "expire", expire, "error", err)
	} else {
		h.Log.Info("client disconnected", "client", cl.ID, "expire", expire)
	}

	if ok && cd.IsMeshDevice() && err != nil {
		sessionDuration := time.Since(cd.ConnectedAt)
		if sessionDuration < 15*time.Second {
			attrs := []any{
				"client", cl.ID,
				"session_duration", sessionDuration.Round(time.Millisecond),
			}
			if cd.ProxyType != "" {
				attrs = append(attrs, "proxy", cd.ProxyType)
			}
			if cd.ProxyType != "" && sessionDuration >= 7*time.Second && sessionDuration <= 12*time.Second {
				h.Log.Warn("proxy client BLE heartbeat timeout - device is not responding to the mobile app", attrs...)
			} else {
				h.Log.Warn("mesh client disconnected shortly after connecting", attrs...)
			}
		}
	}

	if deleted {
		for _, listener := range h.listeners {
			go listener.OnClientDisconnected(cd)
		}
		go h.NotifyClientChange()
	}
}

// GetAllClients returns all currently connected clients.
func (h *AuthHook) GetAllClients() []*models.ClientDetails {
	h.clientLock.RLock()
	clients := make([]*models.ClientDetails, 0, len(h.knownClients))
	for _, c := range h.knownClients {
		clients = append(clients, c)
	}
	h.clientLock.RUnlock()
	return clients
}

// GetUserClients returns all clients for a given MQTT username.
func (h *AuthHook) GetUserClients(mqttUser string) []*models.ClientDetails {
	h.clientLock.RLock()
	clients := make([]*models.ClientDetails, 0, len(h.knownClients))
	for _, c := range h.knownClients {
		if c.MqttUserName == mqttUser {
			clients = append(clients, c)
		}
	}
	h.clientLock.RUnlock()
	return clients
}

// GetClient returns the client details for a given MQTT client ID.
func (h *AuthHook) GetClient(clientID string) *models.ClientDetails {
	h.clientLock.RLock()
	defer h.clientLock.RUnlock()
	return h.knownClients[clientID]
}

// GetClientByNodeID returns the client details for a Meshtastic node ID.
func (h *AuthHook) GetClientByNodeID(nodeID meshtastic.NodeID) *models.ClientDetails {
	h.clientLock.RLock()
	defer h.clientLock.RUnlock()
	for _, client := range h.knownClients {
		if client.NodeDetails != nil && client.NodeDetails.NodeID == nodeID {
			return client
		}
	}
	return nil
}

// NotifyClientChange triggers SSE notifications that clients have changed.
func (h *AuthHook) NotifyClientChange() {
	if h.config.ClientNotifier != nil {
		h.config.ClientNotifier.Notify()
	}
}
