package meshsense

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	meshtastic "github.com/kabili207/meshtastic-go/core"
)

const (
	DefaultURL     = "https://meshsense.affirmatech.com"
	versionString  = "1.0.18"
	requestTimeout = 3 * time.Second
)

// Client sends node updates to a MeshSense server.
type Client struct {
	url        string
	sourceNode uint32
	sourceName string
	httpClient *http.Client
}

// nodeUpdate is the JSON payload sent to MeshSense.
type nodeUpdate struct {
	Source  uint32         `json:"source"`
	Name    string         `json:"name"`
	Updates map[string]any `json:"updates"`
	Version string         `json:"version"`
}

// NewClient creates a MeshSense client. If url is empty, DefaultURL is used.
func NewClient(url string, sourceNode meshtastic.NodeID, sourceName string) *Client {
	if url == "" {
		url = DefaultURL
	}
	return &Client{
		url:        url,
		sourceNode: uint32(sourceNode),
		sourceName: sourceName,
		httpClient: &http.Client{Timeout: requestTimeout},
	}
}

// SendUpdate posts a partial node update to the MeshSense server.
// This should be called from a goroutine — it blocks until the request completes.
func (c *Client) SendUpdate(nodeNum uint32, updates map[string]any) {
	payload := nodeUpdate{
		Source:  c.sourceNode,
		Name:    c.sourceName,
		Updates: updates,
		Version: versionString,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("meshsense: failed to marshal update", "error", err)
		return
	}

	endpoint := fmt.Sprintf("%s/node", c.url)
	resp, err := c.httpClient.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		slog.Error("meshsense: failed to send update", "error", err, "node", nodeNum)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		slog.Warn("meshsense: server returned error",
			"status", resp.StatusCode,
			"node", nodeNum,
			"response", string(respBody),
			"request", string(body),
		)
	}
}
