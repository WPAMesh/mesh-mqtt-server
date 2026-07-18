package hooks

import (
	"log/slog"
	"testing"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/kabili207/mesh-mqtt-server/pkg/config"
)

// TestMeshCoreHookIgnoresObserverTopics verifies the legacy bridge hook does not
// try to base64-decode observer feed topics ({prefix}/{IATA}/{PUBKEY}/{...}),
// which share the "meshcore" prefix but carry JSON, not base64 packets. The
// multi-segment guard must return before any Storage access, so a nil Storage
// here would panic if the guard regressed.
func TestMeshCoreHookIgnoresObserverTopics(t *testing.T) {
	h := &MeshCoreHook{
		config: &MeshCoreHookOptions{
			Settings: config.MeshCoreSettings{
				Enabled:     true,
				TopicPrefix: "meshcore",
			},
			// Storage intentionally nil: observer topics must be skipped before use.
		},
	}
	h.Log = slog.Default()

	cl := &mqtt.Client{}
	cl.ID = "meshcore-observer-7a3abc4e"

	for _, topic := range []string{
		"meshcore/PIT/7A3ABC/status",
		"meshcore/PIT/7A3ABC/packets",
	} {
		pk := packets.Packet{TopicName: topic, Payload: []byte(`{"status":"online"}`)}
		out, err := h.OnPublish(cl, pk)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", topic, err)
		}
		if out.TopicName != topic {
			t.Fatalf("%s: packet modified", topic)
		}
	}
}
