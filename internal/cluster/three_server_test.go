package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/clustertopology"
)

func testThreeServerInventory() clustertopology.Inventory {
	return clustertopology.Inventory{
		Topology: clustertopology.ThreeServerEtcdV1, BootstrapNode: "server-a",
		Nodes: []clustertopology.Node{{Name: "server-a", Address: "10.0.0.11"}, {Name: "server-b", Address: "10.0.0.12"}, {Name: "server-c", Address: "10.0.0.13"}},
	}
}

func testThreeServerNodes() []map[string]any {
	var nodes []map[string]any
	for i, name := range []string{"server-a", "server-b", "server-c"} {
		nodes = append(nodes, map[string]any{
			"metadata": map[string]any{"name": name, "uid": "uid-" + name, "labels": map[string]string{"node-role.kubernetes.io/control-plane": "true", "node-role.kubernetes.io/etcd": "true"}},
			"spec":     map[string]any{"unschedulable": false},
			"status": map[string]any{
				"addresses":  []map[string]string{{"type": "InternalIP", "address": testThreeServerInventory().Nodes[i].Address}},
				"conditions": []map[string]string{{"type": "Ready", "status": "True"}},
				"nodeInfo":   map[string]string{"kubeletVersion": "v1.30.4+k3s1"},
			},
		})
	}
	return nodes
}

func checkThreeServerNodes(t *testing.T, nodes []map[string]any) InventoryHealth {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"items": nodes})
	if err != nil {
		t.Fatal(err)
	}
	run := func(_ context.Context, name string, args ...string) (string, error) {
		if name != "kubectl" || !strings.Contains(strings.Join(args, " "), "get nodes -o json") {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return string(raw), nil
	}
	return ValidateThreeServerNodeReadiness(context.Background(), run, "kubeconfig", testThreeServerInventory(), "v1.30.4+k3s1", map[string]string{"server-a": "uid-server-a"})
}

func TestThreeServerNodeReadiness(t *testing.T) {
	if health := checkThreeServerNodes(t, testThreeServerNodes()); !health.Healthy {
		t.Fatalf("expected healthy nodes, got %+v", health)
	}
	tests := []struct {
		name string
		edit func([]map[string]any) []map[string]any
	}{
		{"two nodes", func(nodes []map[string]any) []map[string]any { return nodes[:2] }},
		{"foreign node", func(nodes []map[string]any) []map[string]any {
			nodes[2]["metadata"].(map[string]any)["name"] = "server-d"
			return nodes
		}},
		{"replacement UID", func(nodes []map[string]any) []map[string]any {
			nodes[0]["metadata"].(map[string]any)["uid"] = "replacement"
			return nodes
		}},
		{"not etcd", func(nodes []map[string]any) []map[string]any {
			delete(nodes[1]["metadata"].(map[string]any)["labels"].(map[string]string), "node-role.kubernetes.io/etcd")
			return nodes
		}},
		{"cordoned", func(nodes []map[string]any) []map[string]any {
			nodes[1]["spec"].(map[string]any)["unschedulable"] = true
			return nodes
		}},
		{"tainted", func(nodes []map[string]any) []map[string]any {
			nodes[1]["spec"].(map[string]any)["taints"] = []map[string]string{{"effect": "NoSchedule"}}
			return nodes
		}},
		{"wrong version", func(nodes []map[string]any) []map[string]any {
			nodes[1]["status"].(map[string]any)["nodeInfo"].(map[string]string)["kubeletVersion"] = "v1.29.0+k3s1"
			return nodes
		}},
		{"wrong address", func(nodes []map[string]any) []map[string]any {
			nodes[1]["status"].(map[string]any)["addresses"] = []map[string]string{{"type": "InternalIP", "address": "10.0.0.99"}}
			return nodes
		}},
		{"not ready", func(nodes []map[string]any) []map[string]any {
			nodes[1]["status"].(map[string]any)["conditions"] = []map[string]string{{"type": "Ready", "status": "False"}}
			return nodes
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if health := checkThreeServerNodes(t, tt.edit(testThreeServerNodes())); health.Healthy {
				t.Fatalf("invalid servers were accepted: %+v", health)
			}
		})
	}
}

func TestThreeServerAPIEndpoints(t *testing.T) {
	inventory := testThreeServerInventory()
	seen := []string{}
	run := func(_ context.Context, name string, args ...string) (string, error) {
		if name != "kubectl" || !strings.Contains(strings.Join(args, " "), "get --raw=/readyz") {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		for i := range args {
			if args[i] == "--server" && i+1 < len(args) {
				seen = append(seen, args[i+1])
			}
		}
		return "ok\n", nil
	}
	if health := ValidateThreeServerAPIEndpoints(context.Background(), run, "kubeconfig", inventory); !health.Healthy {
		t.Fatalf("valid direct endpoints rejected: %+v", health)
	}
	if got, want := strings.Join(seen, ","), strings.Join(inventory.APIEndpoints(), ","); got != want {
		t.Fatalf("checked endpoints = %q, want %q", got, want)
	}
	failure := ValidateThreeServerAPIEndpoints(context.Background(), func(_ context.Context, _ string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "10.0.0.12") {
			return "", fmt.Errorf("connection refused")
		}
		return "ok", nil
	}, "kubeconfig", inventory)
	if failure.Healthy || !strings.Contains(failure.Message, "10.0.0.12") {
		t.Fatalf("unreachable direct endpoint accepted: %+v", failure)
	}
}

func TestNodeReadinessAcceptsSingleEmbeddedEtcdServer(t *testing.T) {
	inventory := clustertopology.Inventory{
		Topology: clustertopology.EmbeddedEtcdV1, BootstrapNode: "server-a",
		Nodes: []clustertopology.Node{{Name: "server-a", Address: "10.0.0.11"}},
	}
	raw, err := json.Marshal(map[string]any{"items": []map[string]any{{
		"metadata": map[string]any{"name": "server-a", "uid": "uid-server-a", "labels": map[string]string{"node-role.kubernetes.io/control-plane": "true", "node-role.kubernetes.io/etcd": "true"}},
		"spec":     map[string]any{"unschedulable": false},
		"status": map[string]any{
			"addresses":  []map[string]string{{"type": "InternalIP", "address": "10.0.0.11"}},
			"conditions": []map[string]string{{"type": "Ready", "status": "True"}},
			"nodeInfo":   map[string]string{"kubeletVersion": "v1.30.4+k3s1"},
		},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	run := func(_ context.Context, _ string, _ ...string) (string, error) { return string(raw), nil }
	if health := ValidateThreeServerNodeReadiness(context.Background(), run, "kubeconfig", inventory, "v1.30.4+k3s1", map[string]string{"server-a": "uid-server-a"}); !health.Healthy {
		t.Fatalf("single embedded-etcd server rejected: %+v", health)
	}
}
