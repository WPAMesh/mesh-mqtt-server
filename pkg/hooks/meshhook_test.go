package hooks

import (
	"log/slog"
	"testing"
)

// TestMeshtasticHookStopIdempotent verifies Stop can be called more than once
// without panicking. mochi's server.Close calls Hook.Stop on every hook, and
// the process may also stop hooks directly, so a double Stop must be safe.
func TestMeshtasticHookStopIdempotent(t *testing.T) {
	h := &MeshtasticHook{stopChan: make(chan struct{})}
	h.Log = slog.Default()

	if err := h.Stop(); err != nil {
		t.Fatalf("first Stop returned error: %v", err)
	}
	// Second call must not panic on the already-closed stopChan.
	if err := h.Stop(); err != nil {
		t.Fatalf("second Stop returned error: %v", err)
	}
}
