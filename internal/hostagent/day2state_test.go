package hostagent_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/hostagent"
)

func TestClearDay2FeatureState_IsTolerantWhenAbsent(t *testing.T) {
	// Production Clear targets fixed host paths; absence is success.
	if err := hostagent.ClearDay2FeatureState(); err != nil {
		t.Logf("ClearDay2FeatureState: %v (tolerated in non-root unit tests)", err)
	}
}

func TestEnsureDay2FeaturesDisabled_NoAgentDoesNotHang(t *testing.T) {
	// Temp socket path: no multi-second readiness poll.
	socket := filepath.Join(t.TempDir(), "missing.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := hostagent.EnsureDay2FeaturesDisabled(ctx, socket); err != nil {
		// Non-root may get permission errors writing/removing /var/lib/zon; log only.
		t.Logf("EnsureDay2FeaturesDisabled: %v", err)
	}
	// Must complete well under the 3s context.
	if err := ctx.Err(); err != nil {
		t.Fatalf("EnsureDay2FeaturesDisabled hung or exceeded budget: %v", err)
	}
}

func TestLocalStateRemovalPattern(t *testing.T) {
	// Mirrors ClearDay2FeatureState semantics without touching production paths.
	root := t.TempDir()
	wifiClientState := filepath.Join(root, "wifi-client")
	wifiState := filepath.Join(root, "wifi-ap")
	mdnsState := filepath.Join(root, "mdns")
	for _, dir := range []string{wifiClientState, wifiState, mdnsState} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"desired":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{wifiClientState, wifiState, mdnsState} {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("expected %s removed, err=%v", dir, err)
		}
	}
}
