package install

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/bundle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/clustertopology"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

type topologyOnlySource struct{}

func (topologyOnlySource) Resolve(context.Context, string) (Resolved, []evidence.Check, error) {
	return Resolved{Compatibility: bundle.Compatibility{DeploymentTopology: clustertopology.EmbeddedEtcdV1}}, nil, nil
}

func TestLegacyInstallRejectsThreeServerReleaseBeforeMutation(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "installed-state.json")
	inventoryPath := filepath.Join(t.TempDir(), "inventory.json")
	inventory := clustertopology.Inventory{
		Topology: clustertopology.ThreeServerEtcdV1, BootstrapNode: "server-a",
		Nodes: []clustertopology.Node{{Name: "server-a", Address: "10.0.0.11"}, {Name: "server-b", Address: "10.0.0.12"}, {Name: "server-c", Address: "10.0.0.13"}},
	}
	data, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inventoryPath, data, 0o640); err != nil {
		t.Fatal(err)
	}
	orch := &Orchestrator{LocalAddresses: func() ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.11")}, nil
	}}
	_, _, err = orch.Install(context.Background(), topologyOnlySource{}, Options{InstalledStatePath: statePath, ClusterInventoryPath: inventoryPath, NodeName: "server-a"})
	if err == nil || !strings.Contains(err.Error(), "embedded-etcd coordinator") {
		t.Fatalf("expected safe topology rejection, got %v", err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("legacy install wrote state before rejecting topology: %v", err)
	}
}

func TestThreeServerInstallRequiresInventoryBeforeMutation(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "installed-state.json")
	_, _, err := (&Orchestrator{}).Install(context.Background(), topologyOnlySource{}, Options{InstalledStatePath: statePath, NodeName: "server-a"})
	if err == nil || !strings.Contains(err.Error(), "inventory") {
		t.Fatalf("expected inventory preflight failure, got %v", err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state was written before inventory preflight: %v", err)
	}
}

func TestThreeServerFinalizationCannotBypassBootstrapAndInventoryFence(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "installed-state.json")
	inventoryPath := filepath.Join(t.TempDir(), "inventory.json")
	inventory := clustertopology.Inventory{
		Topology: clustertopology.ThreeServerEtcdV1, BootstrapNode: "server-a",
		Nodes: []clustertopology.Node{{Name: "server-a", Address: "10.0.0.11"}, {Name: "server-b", Address: "10.0.0.12"}, {Name: "server-c", Address: "10.0.0.13"}},
	}
	data, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inventoryPath, data, 0o640); err != nil {
		t.Fatal(err)
	}
	orch := &Orchestrator{LocalAddresses: func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("10.0.0.12")}, nil }}
	_, _, err = orch.Install(context.Background(), topologyOnlySource{}, Options{
		InstalledStatePath: statePath, ClusterInventoryPath: inventoryPath, NodeName: "server-b",
		ThreeServerFinalization: &ThreeServerFinalization{ClusterID: "cluster-1", ControlPlaneNode: "server-a", ControlEndpoint: inventory.BootstrapAPIEndpoint(), ControlEndpoints: inventory.APIEndpoints(), Nodes: []state.ClusterNode{{Name: "server-a"}, {Name: "server-b"}, {Name: "server-c"}}},
	})
	if err == nil || !strings.Contains(err.Error(), "finalization does not match") {
		t.Fatalf("non-bootstrap finalization bypassed fence: %v", err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("invalid finalization wrote state: %v", err)
	}
}

func TestThreeServerFinalizationSetComparison(t *testing.T) {
	if !sameStringSet([]string{"a", "b", "c"}, []string{"c", "a", "b"}) {
		t.Fatal("equivalent endpoint sets differ")
	}
	if sameStringSet([]string{"a", "b", "c"}, []string{"a", "b", "d"}) {
		t.Fatal("different endpoint sets were accepted")
	}
}

func TestValidatePackTopologies(t *testing.T) {
	foundation := &bundle.Bundle{Compatibility: bundle.Compatibility{DeploymentTopology: clustertopology.EmbeddedEtcdV1}}
	matching := &bundle.Bundle{Compatibility: bundle.Compatibility{DeploymentTopology: clustertopology.EmbeddedEtcdV1}}
	legacy := &bundle.Bundle{}
	if err := validatePackTopologies(foundation, []*bundle.Bundle{matching}); err != nil {
		t.Fatalf("matching pack rejected: %v", err)
	}
	if err := validatePackTopologies(foundation, []*bundle.Bundle{legacy}); err == nil {
		t.Fatal("pack without required topology was accepted")
	}
	if err := validatePackTopologies(legacy, []*bundle.Bundle{matching}); err == nil {
		t.Fatal("new topology pack was accepted with legacy foundation")
	}
}
