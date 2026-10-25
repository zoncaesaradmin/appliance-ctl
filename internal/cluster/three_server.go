package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/clustertopology"
)

// ValidateThreeServerAPIEndpoints proves that each directly addressed API
// server accepts the locally trusted credential. Its one- or three-address
// contract leaves endpoint retry to the caller rather than introducing a
// floating address or load balancer.
func ValidateThreeServerAPIEndpoints(ctx context.Context, run cli.Runner, kubeconfig string, inventory clustertopology.Inventory) InventoryHealth {
	if err := inventory.Validate(); err != nil {
		return InventoryHealth{Checked: true, Message: err.Error()}
	}
	if run == nil || strings.TrimSpace(kubeconfig) == "" {
		return InventoryHealth{Checked: true, Message: "Kubernetes runner and kubeconfig are required"}
	}
	for _, endpoint := range inventory.APIEndpoints() {
		raw, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--server", endpoint, "get", "--raw=/readyz")
		if err != nil {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("direct API endpoint %q is unavailable: %v", endpoint, err)}
		}
		if strings.TrimSpace(raw) != "ok" {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("direct API endpoint %q readiness response is %q", endpoint, strings.TrimSpace(raw))}
		}
	}
	return InventoryHealth{Checked: true, Healthy: true, Message: fmt.Sprintf("all %d direct Kubernetes API endpoints accept the trusted cluster credential", len(inventory.Nodes))}
}

// ValidateThreeServerNodeReadiness checks the live Kubernetes half of the
// embedded-etcd gate. It does not claim etcd quorum: a separate authenticated
// member-list check is required before chart deployment or HA status.
func ValidateThreeServerNodeReadiness(ctx context.Context, run cli.Runner, kubeconfig string, inventory clustertopology.Inventory, k3sVersion string, recordedUIDs map[string]string) InventoryHealth {
	if err := inventory.Validate(); err != nil {
		return InventoryHealth{Checked: true, Message: err.Error()}
	}
	if run == nil || strings.TrimSpace(kubeconfig) == "" || strings.TrimSpace(k3sVersion) == "" {
		return InventoryHealth{Checked: true, Message: "Kubernetes runner, kubeconfig, and signed K3s version are required"}
	}
	raw, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "get", "nodes", "-o", "json")
	if err != nil {
		return InventoryHealth{Checked: true, Message: fmt.Sprintf("query Kubernetes servers: %v", err)}
	}
	var response struct {
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				UID    string            `json:"uid"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Spec struct {
				Unschedulable bool `json:"unschedulable"`
				Taints        []struct {
					Effect string `json:"effect"`
				} `json:"taints"`
			} `json:"spec"`
			Status struct {
				Addresses []struct {
					Type    string `json:"type"`
					Address string `json:"address"`
				} `json:"addresses"`
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
				NodeInfo struct {
					KubeletVersion string `json:"kubeletVersion"`
				} `json:"nodeInfo"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(raw), &response); err != nil {
		return InventoryHealth{Checked: true, Message: fmt.Sprintf("decode Kubernetes servers: %v", err)}
	}
	if len(response.Items) != len(inventory.Nodes) {
		return InventoryHealth{Checked: true, Message: fmt.Sprintf("expected exactly %d Kubernetes server nodes, observed %d", len(inventory.Nodes), len(response.Items))}
	}
	expected := make(map[string]string, len(inventory.Nodes))
	for _, node := range inventory.Nodes {
		expected[node.Name] = node.Address
	}
	seen := make(map[string]struct{}, len(inventory.Nodes))
	for _, node := range response.Items {
		name := strings.TrimSpace(node.Metadata.Name)
		serverIP, found := expected[name]
		if !found {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("unplanned Kubernetes node %q is present", name)}
		}
		if _, duplicate := seen[name]; duplicate {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("duplicate Kubernetes node %q", name)}
		}
		seen[name] = struct{}{}
		if node.Metadata.UID == "" || (recordedUIDs[name] != "" && recordedUIDs[name] != node.Metadata.UID) {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("Kubernetes node %q UID is missing or differs from its recorded identity", name)}
		}
		if _, ok := node.Metadata.Labels["node-role.kubernetes.io/control-plane"]; !ok {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("Kubernetes node %q is not labelled control-plane", name)}
		}
		if _, ok := node.Metadata.Labels["node-role.kubernetes.io/etcd"]; !ok {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("Kubernetes node %q is not labelled etcd", name)}
		}
		if node.Spec.Unschedulable {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("Kubernetes node %q is cordoned", name)}
		}
		for _, taint := range node.Spec.Taints {
			if taint.Effect == "NoSchedule" || taint.Effect == "NoExecute" {
				return InventoryHealth{Checked: true, Message: fmt.Sprintf("Kubernetes node %q has a blocking taint", name)}
			}
		}
		if node.Status.NodeInfo.KubeletVersion != k3sVersion {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("Kubernetes node %q reports K3s %q, expected signed %q", name, node.Status.NodeInfo.KubeletVersion, k3sVersion)}
		}
		ready, addressMatches := false, false
		for _, condition := range node.Status.Conditions {
			if condition.Type == "Ready" && condition.Status == "True" {
				ready = true
			}
		}
		for _, address := range node.Status.Addresses {
			if address.Type == "InternalIP" && address.Address == serverIP {
				addressMatches = true
			}
		}
		if !ready || !addressMatches {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("Kubernetes node %q is not Ready on its planned server address", name)}
		}
	}
	return InventoryHealth{Checked: true, Healthy: true, Message: fmt.Sprintf("all %d planned schedulable control-plane/etcd nodes are Ready on the signed K3s version; etcd membership remains to be checked", len(inventory.Nodes))}
}
