package cluster

import (
	"context"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

func TestNodeUIDUsesKubernetesMetadata(t *testing.T) {
	uid, err := NodeUID(context.Background(), func(_ context.Context, name string, args ...string) (string, error) {
		if name != "kubectl" || !strings.Contains(strings.Join(args, " "), "jsonpath={.metadata.uid}") {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "6e6e3a3d-cd01-48c7-b8cc-3a5150ddc1ad", nil
	}, "/etc/rancher/k3s/k3s.yaml", "control-1")
	if err != nil || uid != "6e6e3a3d-cd01-48c7-b8cc-3a5150ddc1ad" {
		t.Fatalf("NodeUID = %q, %v", uid, err)
	}
}

func TestValidateInventoryRequiresRecordedReadyUIDs(t *testing.T) {
	run := func(_ context.Context, _ string, _ ...string) (string, error) {
		return `{"items":[{"metadata":{"name":"control","uid":"uid-control"},"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"gpu","uid":"uid-gpu"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`, nil
	}
	health := ValidateInventory(context.Background(), run, "kubeconfig", []state.ClusterNode{{Name: "control", NodeUID: "uid-control"}, {Name: "gpu", NodeUID: "uid-gpu"}})
	if !health.Checked || !health.Healthy {
		t.Fatalf("inventory health = %+v", health)
	}
}

func TestValidateInventoryRejectsUnknownOrReplacedNode(t *testing.T) {
	run := func(_ context.Context, _ string, _ ...string) (string, error) {
		return `{"items":[{"metadata":{"name":"control","uid":"replacement"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`, nil
	}
	health := ValidateInventory(context.Background(), run, "kubeconfig", []state.ClusterNode{{Name: "control", NodeUID: "original"}})
	if !health.Checked || health.Healthy || !strings.Contains(health.Message, "does not match") {
		t.Fatalf("inventory health = %+v", health)
	}
}

func TestValidateWorkerUpgradeReadinessRequiresEveryWorkerAtTarget(t *testing.T) {
	run := func(_ context.Context, _ string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "get nodes -o json"):
			return `{"items":[{"metadata":{"name":"control","uid":"uid-control"},"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"gpu","uid":"uid-gpu"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`, nil
		case strings.Contains(joined, "get node gpu"):
			return "v1.30.4+k3s1", nil
		default:
			t.Fatalf("unexpected command: %v", args)
			return "", nil
		}
	}
	nodes := []state.ClusterNode{{Name: "control", NodeUID: "uid-control", Role: state.NodeRoleControlPlane}, {Name: "gpu", NodeUID: "uid-gpu", Role: state.NodeRoleInference}}
	if health := ValidateWorkerUpgradeReadiness(context.Background(), run, "kubeconfig", nodes, "v1.30.4+k3s1"); !health.Healthy {
		t.Fatalf("expected ready workers, got %+v", health)
	}
	if health := ValidateWorkerUpgradeReadiness(context.Background(), run, "kubeconfig", nodes, "v1.31.0+k3s1"); health.Healthy || !strings.Contains(health.Message, "upgrade it locally") {
		t.Fatalf("expected target-version rejection, got %+v", health)
	}
}
