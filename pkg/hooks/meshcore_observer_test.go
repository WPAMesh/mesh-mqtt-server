package hooks

import (
	"log/slog"
	"testing"

	mqtt "github.com/mochi-mqtt/server/v2"

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

// clientWithUser builds a live connection carrying the given authenticated username.
func clientWithUser(user string) *mqtt.Client {
	cl := &mqtt.Client{}
	cl.Properties.Username = []byte(user)
	return cl
}

func TestObserverCheckACL_ObserverClient(t *testing.T) {
	h := newObserverHook(t)
	observer := &models.ClientDetails{IsMeshCoreObserver: true, ClientID: "obs1"}

	// Observers may read and write anywhere in the prefix.
	for _, write := range []bool{false, true} {
		handled, allowed := h.CheckACL(observer, nil, "meshcore/AGC/DEADBEEF/packets", write)
		if !handled || !allowed {
			t.Fatalf("observer write=%v: got (%v,%v), want (true,true)", write, handled, allowed)
		}
	}

	// Observers are denied outside the prefix.
	handled, allowed := h.CheckACL(observer, nil, "msh/US/2/e/LongFast/!abcd", false)
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
		handled, allowed := h.CheckACL(tool, clientWithUser("mapper"), topic, false)
		if !handled || !allowed {
			t.Fatalf("map read %q: got (%v,%v), want (true,true)", topic, handled, allowed)
		}
	}

	// Writes to the observer feed are denied.
	handled, allowed := h.CheckACL(tool, clientWithUser("mapper"), "meshcore/AGC/DEADBEEF/packets", true)
	if !handled || allowed {
		t.Fatalf("map write: got (%v,%v), want (true,false)", handled, allowed)
	}

	// A bridge-shaped topic (2 segments) is not an observer feed topic, so the
	// observer hook does not claim it and lets other checkers decide.
	handled, _ = h.CheckACL(tool, clientWithUser("mapper"), "meshcore/somebridge", false)
	if handled {
		t.Fatal("bridge topic should be left to other checkers")
	}

	// Non-observer topics are not claimed.
	handled, _ = h.CheckACL(tool, clientWithUser("mapper"), "msh/US/2/e/LongFast/!abcd", false)
	if handled {
		t.Fatal("mesh topic should be left to other checkers")
	}
}

// TestObserverCheckACL_ClientIDCollision covers a client reusing one client ID
// across two connections (observer + non-observer). The shared ClientDetails
// may carry the wrong observer flag, so the decision must come from the live
// connection's authenticated username.
func TestObserverCheckACL_ClientIDCollision(t *testing.T) {
	h := newObserverHook(t)

	// Cached entry says non-observer (the stale mesht-* connection won the map),
	// but the live connection authenticated as an observer. Its feed write must
	// be allowed.
	staleCD := &models.ClientDetails{ClientID: "ESP32_x", IsMeshCoreObserver: false}
	live := clientWithUser("v1_AC6B7DD0AE2E11E0BA40835E16B4141769566257C96CEC31E23388D2D83ECA42")
	handled, allowed := h.CheckACL(staleCD, live, "meshcore/PIT/AC6B7DD0/status", true)
	if !handled || !allowed {
		t.Fatalf("observer connection with stale non-observer cd: got (%v,%v), want (true,true)", handled, allowed)
	}

	// Reverse: cached entry says observer, but the live connection is a plain
	// user. It must NOT get observer write on the feed.
	staleObsCD := &models.ClientDetails{ClientID: "ESP32_x", IsMeshCoreObserver: true}
	plain := clientWithUser("mesht-nahum")
	handled, allowed = h.CheckACL(staleObsCD, plain, "meshcore/PIT/AC6B7DD0/status", true)
	if !handled || allowed {
		t.Fatalf("plain connection with stale observer cd: got (%v,%v), want (true,false)", handled, allowed)
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
