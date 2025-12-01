package hooks

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"

	pahomqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/kabili207/mesh-mqtt-server/pkg/config"
)

// ForwardingHookOptions contains configuration for the forwarding hook
type ForwardingHookOptions struct {
	Settings config.ForwardingSettings
}

// ForwardingClient represents a connection to an external MQTT server
type ForwardingClient struct {
	Name          string
	Address       string
	Topics        []string
	TopicRewrites map[string]string
	Client        pahomqtt.Client
	Connected     bool
	LastError     error
	LastErrorTime *time.Time
	ConnectedAt   *time.Time
	mu            sync.RWMutex
}

// ForwardingStatus represents the status of a forwarding target for API responses
type ForwardingStatus struct {
	Name          string     `json:"name"`
	Address       string     `json:"address"`
	Connected     bool       `json:"connected"`
	LastError     string     `json:"last_error,omitempty"`
	LastErrorTime *time.Time `json:"last_error_time,omitempty"`
	ConnectedAt   *time.Time `json:"connected_at,omitempty"`
	Topics        []string   `json:"topics"`
}

// ForwardingHook handles forwarding MQTT packets to external servers
type ForwardingHook struct {
	mqtt.HookBase
	config  *ForwardingHookOptions
	clients map[string]*ForwardingClient
	mu      sync.RWMutex
}

func (h *ForwardingHook) ID() string {
	return "forwarding-hook"
}

func (h *ForwardingHook) Provides(b byte) bool {
	return bytes.Contains([]byte{
		mqtt.OnPublish,
	}, []byte{b})
}

func (h *ForwardingHook) Init(config any) error {
	h.Log.Info("initializing forwarding hook")

	if _, ok := config.(*ForwardingHookOptions); !ok && config != nil {
		return mqtt.ErrInvalidConfigType
	}

	h.config = config.(*ForwardingHookOptions)
	h.clients = make(map[string]*ForwardingClient)

	if !h.config.Settings.Enabled {
		h.Log.Info("forwarding is disabled")
		return nil
	}

	// Initialize connections to all targets
	for _, target := range h.config.Settings.Targets {
		if err := h.addTarget(target); err != nil {
			h.Log.Error("failed to add forwarding target", "name", target.Name, "error", err)
		}
	}

	return nil
}

// addTarget creates and connects a client for a forwarding target
func (h *ForwardingHook) addTarget(target config.ForwardingTarget) error {
	if target.Name == "" {
		return fmt.Errorf("forwarding target name is required")
	}
	if target.Address == "" {
		return fmt.Errorf("forwarding target address is required")
	}
	if len(target.Topics) == 0 {
		return fmt.Errorf("at least one topic is required for forwarding target %s", target.Name)
	}

	clientID := target.ClientID
	if clientID == "" {
		clientID = fmt.Sprintf("mesh-forwarder-%s-%d", target.Name, time.Now().UnixNano())
	}

	fc := &ForwardingClient{
		Name:          target.Name,
		Address:       target.Address,
		Topics:        target.Topics,
		TopicRewrites: target.TopicRewrites,
	}

	// Configure MQTT client options
	scheme := "tcp"
	if target.UseTLS {
		scheme = "ssl"
	}
	brokerURL := fmt.Sprintf("%s://%s", scheme, target.Address)

	opts := pahomqtt.NewClientOptions().
		AddBroker(brokerURL).
		SetClientID(clientID).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(5 * time.Second).
		SetMaxReconnectInterval(2 * time.Minute).
		SetKeepAlive(60 * time.Second).
		SetPingTimeout(10 * time.Second).
		SetCleanSession(true).
		SetOrderMatters(false).
		SetOnConnectHandler(func(c pahomqtt.Client) {
			h.onClientConnected(target.Name)
		}).
		SetConnectionLostHandler(func(c pahomqtt.Client, err error) {
			h.onClientDisconnected(target.Name, err)
		}).
		SetReconnectingHandler(func(c pahomqtt.Client, opts *pahomqtt.ClientOptions) {
			h.Log.Info("reconnecting to forwarding target", "name", target.Name, "address", target.Address)
		})

	if target.Username != "" {
		opts.SetUsername(target.Username)
	}
	if target.Password != "" {
		opts.SetPassword(target.Password)
	}
	if target.UseTLS {
		opts.SetTLSConfig(&tls.Config{
			MinVersion: tls.VersionTLS12,
		})
	}

	fc.Client = pahomqtt.NewClient(opts)

	h.mu.Lock()
	h.clients[target.Name] = fc
	h.mu.Unlock()

	// Connect in a goroutine to not block initialization
	go func() {
		h.Log.Info("connecting to forwarding target", "name", target.Name, "address", target.Address)
		token := fc.Client.Connect()
		if token.WaitTimeout(30 * time.Second) {
			if token.Error() != nil {
				h.Log.Error("failed to connect to forwarding target", "name", target.Name, "error", token.Error())
				fc.mu.Lock()
				fc.LastError = token.Error()
				now := time.Now()
				fc.LastErrorTime = &now
				fc.mu.Unlock()
			}
		} else {
			h.Log.Warn("connection timeout to forwarding target", "name", target.Name)
		}
	}()

	return nil
}

func (h *ForwardingHook) onClientConnected(name string) {
	h.mu.RLock()
	fc, ok := h.clients[name]
	h.mu.RUnlock()

	if !ok {
		return
	}

	fc.mu.Lock()
	fc.Connected = true
	now := time.Now()
	fc.ConnectedAt = &now
	fc.LastError = nil
	fc.LastErrorTime = nil
	fc.mu.Unlock()

	h.Log.Info("connected to forwarding target", "name", name, "address", fc.Address)
}

func (h *ForwardingHook) onClientDisconnected(name string, err error) {
	h.mu.RLock()
	fc, ok := h.clients[name]
	h.mu.RUnlock()

	if !ok {
		return
	}

	fc.mu.Lock()
	fc.Connected = false
	fc.ConnectedAt = nil
	if err != nil {
		fc.LastError = err
		now := time.Now()
		fc.LastErrorTime = &now
	}
	fc.mu.Unlock()

	h.Log.Warn("disconnected from forwarding target", "name", name, "error", err)
}

// OnPublish intercepts published packets and forwards them to external servers
func (h *ForwardingHook) OnPublish(cl *mqtt.Client, pk packets.Packet) (packets.Packet, error) {
	if !h.config.Settings.Enabled {
		return pk, nil
	}

	// Forward to all connected targets that match the topic
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, fc := range h.clients {
		if !fc.shouldForward(pk.TopicName) {
			continue
		}

		fc.mu.RLock()
		connected := fc.Connected
		fc.mu.RUnlock()

		if !connected {
			continue
		}

		// Apply topic rewriting
		targetTopic := fc.rewriteTopic(pk.TopicName)

		// Forward the packet asynchronously
		go func(client *ForwardingClient, topic string, payload []byte, qos byte, retain bool) {
			token := client.Client.Publish(topic, qos, retain, payload)
			if !token.WaitTimeout(5 * time.Second) {
				slog.Warn("timeout forwarding packet", "target", client.Name, "topic", topic)
			} else if token.Error() != nil {
				slog.Error("error forwarding packet", "target", client.Name, "topic", topic, "error", token.Error())
			}
		}(fc, targetTopic, pk.Payload, pk.FixedHeader.Qos, pk.FixedHeader.Retain)
	}

	return pk, nil
}

// shouldForward checks if a topic matches any of the configured topic patterns
func (fc *ForwardingClient) shouldForward(topic string) bool {
	for _, pattern := range fc.Topics {
		if topicMatches(pattern, topic) {
			return true
		}
	}
	return false
}

// rewriteTopic applies topic rewrite rules to a topic
func (fc *ForwardingClient) rewriteTopic(topic string) string {
	if fc.TopicRewrites == nil {
		return topic
	}

	for pattern, replacement := range fc.TopicRewrites {
		if strings.HasPrefix(topic, pattern) {
			return replacement + topic[len(pattern):]
		}
	}

	return topic
}

// topicMatches checks if a topic matches an MQTT topic pattern (supports + and # wildcards)
func topicMatches(pattern, topic string) bool {
	patternParts := strings.Split(pattern, "/")
	topicParts := strings.Split(topic, "/")

	for i, patternPart := range patternParts {
		if patternPart == "#" {
			// # matches everything from here on
			return true
		}

		if i >= len(topicParts) {
			// Pattern has more parts than topic
			return false
		}

		if patternPart == "+" {
			// + matches exactly one level
			continue
		}

		if patternPart != topicParts[i] {
			return false
		}
	}

	// Pattern and topic must have the same number of parts (unless pattern ended with #)
	return len(patternParts) == len(topicParts)
}

// GetStatus returns the status of all forwarding targets
func (h *ForwardingHook) GetStatus() []ForwardingStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	statuses := make([]ForwardingStatus, 0, len(h.clients))
	for _, fc := range h.clients {
		fc.mu.RLock()
		status := ForwardingStatus{
			Name:          fc.Name,
			Address:       fc.Address,
			Connected:     fc.Connected,
			ConnectedAt:   fc.ConnectedAt,
			LastErrorTime: fc.LastErrorTime,
			Topics:        fc.Topics,
		}
		if fc.LastError != nil {
			status.LastError = fc.LastError.Error()
		}
		fc.mu.RUnlock()
		statuses = append(statuses, status)
	}

	return statuses
}

// Stop gracefully disconnects all forwarding clients
func (h *ForwardingHook) Stop() error {
	h.Log.Info("stopping forwarding hook")

	h.mu.Lock()
	defer h.mu.Unlock()

	for name, fc := range h.clients {
		if fc.Client.IsConnected() {
			h.Log.Info("disconnecting forwarding client", "name", name)
			fc.Client.Disconnect(1000) // Wait up to 1 second for clean disconnect
		}
	}

	return nil
}

// IsEnabled returns whether forwarding is enabled
func (h *ForwardingHook) IsEnabled() bool {
	return h.config != nil && h.config.Settings.Enabled
}
