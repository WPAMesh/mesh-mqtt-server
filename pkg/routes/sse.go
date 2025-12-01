package routes

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/a-h/templ"
	"github.com/kabili207/mesh-mqtt-server/internal/web/components"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
)

// ClientNotifier provides a way to notify SSE subscribers about client changes
type ClientNotifier struct {
	subscribers map[chan struct{}]struct{}
	mu          sync.RWMutex
}

// NewClientNotifier creates a new ClientNotifier
func NewClientNotifier() *ClientNotifier {
	return &ClientNotifier{
		subscribers: make(map[chan struct{}]struct{}),
	}
}

// Subscribe adds a new subscriber that will be notified on client changes
func (cn *ClientNotifier) Subscribe() chan struct{} {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	ch := make(chan struct{}, 1)
	cn.subscribers[ch] = struct{}{}
	return ch
}

// Unsubscribe removes a subscriber
func (cn *ClientNotifier) Unsubscribe(ch chan struct{}) {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	delete(cn.subscribers, ch)
	close(ch)
}

// Notify triggers all subscribers about a change
func (cn *ClientNotifier) Notify() {
	cn.mu.RLock()
	defer cn.mu.RUnlock()
	for ch := range cn.subscribers {
		select {
		case ch <- struct{}{}:
		default:
			// Channel already has a pending notification, skip
		}
	}
}

// SSE endpoint for node updates
func (wr *WebRouter) nodesSSE(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if SSE is supported
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Parse query parameters
	query := r.URL.Query()
	allUsers := query.Get("all_users") == "true"
	isAdmin := user.IsSuperuser && allUsers
	connectedOnly := query.Get("filter-connected") == "on"
	validGatewayOnly := query.Get("filter-gateway") == "on"

	if allUsers && !user.IsSuperuser {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Subscribe to client updates
	if wr.ClientNotifier == nil {
		slog.Warn("SSE endpoint called but ClientNotifier is nil")
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	notifyCh := wr.ClientNotifier.Subscribe()
	defer wr.ClientNotifier.Unsubscribe(notifyCh)

	ctx := r.Context()

	// Send initial data and then updates
	ticker := time.NewTicker(30 * time.Second) // Heartbeat to keep connection alive
	defer ticker.Stop()

	// Helper function to send nodes update
	sendNodesUpdate := func() error {
		nodes, otherClients := wr.getNodesData(user, isAdmin, connectedOnly, validGatewayOnly)

		// Render the template to a buffer
		var buf bytes.Buffer
		var comp templ.Component

		if isAdmin {
			comp = components.NodesTableContent(nodes, true)
		} else {
			comp = components.NodeGridContent(nodes)
		}

		if err := comp.Render(ctx, &buf); err != nil {
			return err
		}

		// Send SSE event for nodes
		_, err := fmt.Fprintf(w, "event: nodes-update\ndata: %s\n\n", escapeSSEData(buf.String()))
		if err != nil {
			return err
		}

		// Send other clients update
		buf.Reset()
		if err := components.OtherClientsTableContent(otherClients, isAdmin).Render(ctx, &buf); err != nil {
			return err
		}

		_, err = fmt.Fprintf(w, "event: other-clients-update\ndata: %s\n\n", escapeSSEData(buf.String()))
		if err != nil {
			return err
		}

		flusher.Flush()
		return nil
	}

	// Send initial data
	if err := sendNodesUpdate(); err != nil {
		slog.Error("error sending initial SSE data", "error", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-notifyCh:
			// Client update notification received
			if err := sendNodesUpdate(); err != nil {
				slog.Error("error sending SSE update", "error", err)
				return
			}
		case <-ticker.C:
			// Send heartbeat comment to keep connection alive
			_, err := fmt.Fprintf(w, ": heartbeat\n\n")
			if err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// escapeSSEData escapes newlines for SSE data format
func escapeSSEData(s string) string {
	// SSE requires newlines to be sent as separate data: lines
	// For simplicity, we'll use a single-line format by replacing newlines
	// with HTML entities (the browser will render them correctly)
	var result bytes.Buffer
	for _, c := range s {
		switch c {
		case '\n':
			result.WriteString("\\n")
		case '\r':
			// Skip carriage returns
		default:
			result.WriteRune(c)
		}
	}
	return result.String()
}

// getNodesData retrieves nodes and other clients data for display
func (wr *WebRouter) getNodesData(user *models.User, allUsers bool, connectedOnly bool, validGatewayOnly bool) ([]components.NodeData, []components.OtherClientData) {
	var clients []*models.ClientDetails
	if allUsers {
		clients = wr.MqttServer.GetAllClients()
	} else {
		clients = wr.MqttServer.GetUserClients(user.UserName)
	}

	nodes := []components.NodeData{}
	otherClients := []components.OtherClientData{}

	knownNodes := []uint32{}
	for _, c := range clients {
		if connectedOnly && c.Address == "" {
			continue
		}

		ipAddr, _ := c.GetIPAddress()

		userDisplay := ""
		if allUsers {
			userDisplay = wr.getUserDisplay(c.MqttUserName)
		}

		if !c.IsMeshDevice() {
			otherClients = append(otherClients, components.OtherClientData{
				ClientID:    c.ClientID,
				Address:     ipAddr,
				UserDisplay: userDisplay,
			})
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

		nodeColor := ""
		if c.NodeDetails != nil {
			nodeColor = c.NodeDetails.GetNodeColor()
		}

		nodes = append(nodes, components.NodeData{
			NodeID:           nodeID,
			ShortName:        c.GetShortName(),
			LongName:         c.GetLongName(),
			NodeColor:        nodeColor,
			ProxyType:        c.ProxyType,
			Address:          c.Address,
			RootTopic:        c.RootTopic,
			NodeRole:         nodeRole,
			HwModel:          hwModel,
			LastSeen:         lastSeen,
			IsDownlink:       c.IsDownlinkVerified(),
			IsValidGateway:   c.IsValidGateway(),
			IsConnected:      c.Address != "",
			IsMeshDevice:     true,
			ClientID:         c.ClientID,
			UserDisplay:      userDisplay,
			ValidationErrors: c.GetValidationErrors(),
		})
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

				nodes = append(nodes, components.NodeData{
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

	return nodes, otherClients
}

// nodesHTML returns HTML fragments for htmx requests
func (wr *WebRouter) nodesHTML(w http.ResponseWriter, r *http.Request) {
	session, _ := wr.getSession(r)
	user, err := wr.getUser(session)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	query := r.URL.Query()
	connectedOnly := query.Get("filter-connected") == "on"
	validGatewayOnly := query.Get("filter-gateway") == "on"
	allUsers := query.Get("all_users") == "true"

	if allUsers && !user.IsSuperuser {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	nodes, _ := wr.getNodesData(user, allUsers, connectedOnly, validGatewayOnly)

	w.Header().Set("Content-Type", "text/html")

	var comp templ.Component
	if allUsers {
		comp = components.NodesTableContent(nodes, true)
	} else {
		comp = components.NodeGridContent(nodes)
	}

	if err := comp.Render(r.Context(), w); err != nil {
		slog.Error("error rendering nodes HTML", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// usersHTML returns HTML fragments for htmx requests
func (wr *WebRouter) usersHTML(w http.ResponseWriter, r *http.Request) {
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

	userRows := make([]components.UserRowData, len(users))
	for i, u := range users {
		userRows[i] = components.UserRowData{
			ID:               u.ID,
			UserName:         u.UserName,
			DisplayName:      u.DisplayName,
			IsSuperuser:      u.IsSuperuser,
			IsGatewayAllowed: u.IsGatewayAllowed,
			Created:          u.Created.Format("2006-01-02 15:04:05"),
		}
	}

	w.Header().Set("Content-Type", "text/html")
	if err := components.UsersTableContent(userRows).Render(r.Context(), w); err != nil {
		slog.Error("error rendering users HTML", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
