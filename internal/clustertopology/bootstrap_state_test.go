package clustertopology

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testBootstrapState(t *testing.T) BootstrapState {
	t.Helper()
	in := validInventory()
	fingerprint, err := in.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	return BootstrapState{
		SchemaVersion: BootstrapStateVersion, Topology: EmbeddedEtcdV1,
		InventoryFingerprint: fingerprint, ClusterID: "cluster-1", ReleaseID: "release-1",
		ApplianceName: "zon", ApplianceProfile: "core", DNSZone: "appliance.internal",
		BundleVersion: "2.4.0", K3sVersion: "v1.30.4+k3s1", LocalNode: "server-a",
		Phase: PhasePrepared, CreatedAt: now, UpdatedAt: now,
	}
}

func TestBootstrapStateRoundTripAndRerunFence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap-state.json")
	if state, err := LoadBootstrapState(path); err != nil || state != nil {
		t.Fatalf("fresh host state = %+v, %v", state, err)
	}
	state := testBootstrapState(t)
	if err := SaveBootstrapState(path, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadBootstrapState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.Matches(validInventory(), "release-1", "2.4.0", "v1.30.4+k3s1", "server-a", "zon", "core", "appliance.internal"); err != nil {
		t.Fatalf("same-input rerun rejected: %v", err)
	}
	if err := loaded.Matches(validInventory(), "release-2", "2.4.0", "v1.30.4+k3s1", "server-a", "zon", "core", "appliance.internal"); err == nil {
		t.Fatal("different release accepted for staged cluster")
	}
	if err := loaded.Matches(validInventory(), "release-1", "2.4.0", "v1.30.4+k3s1", "server-b", "zon", "core", "appliance.internal"); err == nil {
		t.Fatal("wrong local node accepted for staged cluster")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("bootstrap state mode = %v, %v", info, err)
	}
}

func TestBootstrapStateRejectsFalseCompletionAndUnknownFields(t *testing.T) {
	state := testBootstrapState(t)
	state.Phase = PhaseJoined
	if err := state.Validate(); err == nil {
		t.Fatal("joined phase without observed UID accepted")
	}
	state.NodeUID = "uid-a"
	if err := state.Validate(); err != nil {
		t.Fatalf("observed node rejected: %v", err)
	}
	path := filepath.Join(t.TempDir(), "bootstrap-state.json")
	if err := SaveBootstrapState(path, state); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), `"phase":`, `"unknown":true,"phase":`, 1)), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBootstrapState(path); err == nil {
		t.Fatal("unknown bootstrap state field accepted")
	}
}
