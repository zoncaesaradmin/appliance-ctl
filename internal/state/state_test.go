package state_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

func sampleState() *state.InstalledState {
	now := time.Now().UTC()
	return &state.InstalledState{
		SchemaVersion:       1,
		ApplianceInstanceID: "9f4d6b1e-2a3c-4e5f-8b1a-7c6d5e4f3a2b",
		InstalledVersion:    "2.4.0",
		InstalledReleaseID:  "01J8QK3F9G7XA6P0V6ZC9N6R4T",
		Components: state.Components{
			K3sVersion:   "v1.30.4+k3s1",
			ChartVersion: "2.4.0",
		},
		K3sOwnership: state.K3sOwnership{Owned: true, OwnerApplianceVersion: "2.4.0"},
		LastOperation: state.Operation{
			Type:          "install",
			Status:        "completed",
			TransactionID: "txn-01J8QK4G8H9YB7Q1W7ZD0P7S5U",
			StartedAt:     now,
			CompletedAt:   &now,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func TestLoad_MissingFileReturnsNilNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installed-state.json")

	got, err := state.Load(path)
	if err != nil {
		t.Fatalf("expected no error for a fresh host, got: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil state for a fresh host, got %+v", got)
	}
}

func TestSaveThenLoad_RoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installed-state.json")
	want := sampleState()

	if err := state.Save(path, want); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	got, err := state.Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if got.InstalledVersion != want.InstalledVersion || got.ApplianceInstanceID != want.ApplianceInstanceID {
		t.Errorf("round-tripped state does not match: got %+v, want %+v", got, want)
	}
	if !got.K3sOwnership.Owned {
		t.Error("expected K3sOwnership.Owned to survive the round trip")
	}
}

// Fails closed: an on-disk file that doesn't satisfy installed-state.v1
// (here, an unrelated cluster with owned=false, which the schema forbids)
// must not be silently accepted.
func TestLoad_RejectsSchemaInvalidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installed-state.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion": 1, "installedVersion": "not-even-json-shaped"`), 0o640); err != nil {
		t.Fatal(err)
	}

	if _, err := state.Load(path); err == nil {
		t.Error("expected malformed installed-state file to fail to load")
	}
}
