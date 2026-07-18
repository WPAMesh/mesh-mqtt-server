package hooks

import (
	"log/slog"
	"testing"

	"github.com/kabili207/mesh-mqtt-server/pkg/config"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
)

func newObserverHook(t *testing.T) *MeshCoreObserverHook {
	t.Helper()
	h := &MeshCoreObserverHook{
		config: &MeshCoreObserverHookOptions{
			Settings: config.MeshCoreObserverSettings{
				Enabled:     true,
				TopicPrefix: "meshcore",
			},
		},
	}
	h.Log = slog.Default()
	return h
}

func TestObserverCheckACL_ObserverClient(t *testing.T) {
	h := newObserverHook(t)
	observer := &models.ClientDetails{IsMeshCoreObserver: true, ClientID: "obs1"}

	// Observers may read and write anywhere in the prefix.
	for _, write := range []bool{false, true} {
		handled, allowed := h.CheckACL(observer, "meshcore/AGC/DEADBEEF/packets", write)
		if !handled || !allowed {
			t.Fatalf("observer write=%v: got (%v,%v), want (true,true)", write, handled, allowed)
		}
	}

	// Observers are denied outside the prefix.
	handled, allowed := h.CheckACL(observer, "msh/US/2/e/LongFast/!abcd", false)
	if !handled || allowed {
		t.Fatalf("observer off-prefix: got (%v,%v), want (true,false)", handled, allowed)
	}
}

func TestObserverCheckACL_MappingTool(t *testing.T) {
	h := newObserverHook(t)
	tool := &models.ClientDetails{ClientID: "mapper", UserID: 7}

	// Read on the observer feed is allowed for non-observer clients.
	for _, topic := range []string{
		"meshcore/AGC/DEADBEEF/packets",
		"meshcore/AGC/DEADBEEF/status",
		"meshcore/+/+/packets",
		"meshcore/+/+/status",
	} {
		handled, allowed := h.CheckACL(tool, topic, false)
		if !handled || !allowed {
			t.Fatalf("map read %q: got (%v,%v), want (true,true)", topic, handled, allowed)
		}
	}

	// Writes to the observer feed are denied.
	handled, allowed := h.CheckACL(tool, "meshcore/AGC/DEADBEEF/packets", true)
	if !handled || allowed {
		t.Fatalf("map write: got (%v,%v), want (true,false)", handled, allowed)
	}

	// A bridge-shaped topic (2 segments) is not an observer feed topic, so the
	// observer hook does not claim it and lets other checkers decide.
	handled, _ = h.CheckACL(tool, "meshcore/somebridge", false)
	if handled {
		t.Fatal("bridge topic should be left to other checkers")
	}

	// Non-observer topics are not claimed.
	handled, _ = h.CheckACL(tool, "msh/US/2/e/LongFast/!abcd", false)
	if handled {
		t.Fatal("mesh topic should be left to other checkers")
	}
}

func TestIsObserverFeedTopic(t *testing.T) {
	prefix := "meshcore/"
	cases := map[string]bool{
		"meshcore/AGC/DEADBEEF/packets": true,
		"meshcore/AGC/DEADBEEF/status":  true,
		"meshcore/+/+/packets":          true,
		"meshcore/AGC/DEADBEEF/other":   false,
		"meshcore/AGC/DEADBEEF/#":       false,
		"meshcore/somebridge":           false,
		"meshcore/AGC/DEADBEEF":         false,
		"msh/US/thing/packets":          false,
	}
	for topic, want := range cases {
		if got := isObserverFeedTopic(topic, prefix); got != want {
			t.Errorf("isObserverFeedTopic(%q) = %v, want %v", topic, got, want)
		}
	}
}
