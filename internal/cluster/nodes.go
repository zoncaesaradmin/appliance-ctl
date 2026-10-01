package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

// InventoryHealth is the control-plane comparison of the authoritative
// appliance inventory and Kubernetes's current Node objects. It is a read-only
// signal used by status/verify/support-bundle before any lifecycle mutation.
type InventoryHealth struct {
	Checked bool
	Healthy bool
	Message string
}

// LabelInferenceNode declares a node eligible for an appliance-managed
// inference release. The labels are written only by zonctl after the local
// K3s API is ready; no workload or discovery process can self-enroll a node.
func LabelInferenceNode(ctx context.Context, run cli.Runner, kubeconfig, nodeName string) error {
	if run == nil {
		return fmt.Errorf("cluster: command runner is required")
	}
	if strings.TrimSpace(kubeconfig) == "" || strings.TrimSpace(nodeName) == "" {
		return fmt.Errorf("cluster: kubeconfig and node name are required")
	}
	_, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "label", "node", nodeName, "--overwrite",
		"zon.io/appliance-node=true", "zon.io/role=inference", "zon.io/inference-node=true")
	if err != nil {
		return fmt.Errorf("cluster: label inference node %q: %w", nodeName, err)
	}
	return nil
}

// NodeUID returns the immutable Kubernetes identity for a registered node.
// Names are placement handles only: a replacement host may reuse one, so
// lifecycle inventory and routing must persist the UID returned here.
func NodeUID(ctx context.Context, run cli.Runner, kubeconfig, nodeName string) (string, error) {
	if run == nil {
		return "", fmt.Errorf("cluster: command runner is required")
	}
	if strings.TrimSpace(kubeconfig) == "" || strings.TrimSpace(nodeName) == "" {
		return "", fmt.Errorf("cluster: kubeconfig and node name are required")
	}
	uid, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "get", "node", nodeName, "-o", "jsonpath={.metadata.uid}")
	if err != nil {
		return "", fmt.Errorf("cluster: get node UID for %q: %w", nodeName, err)
	}
	uid = strings.TrimSpace(uid)
	if uid == "" || strings.ContainsAny(uid, " \t\r\n") {
		return "", fmt.Errorf("cluster: node %q returned an invalid UID", nodeName)
	}
	return uid, nil
}

// ValidateInventory verifies that every Node admitted to the cluster record is
// present under the same immutable UID and Ready in the live Kubernetes
// cluster. It also rejects an unrecorded Node: cluster membership is explicit
// enrollment, never best-effort discovery.
func ValidateInventory(ctx context.Context, run cli.Runner, kubeconfig string, expected []state.ClusterNode) InventoryHealth {
	if run == nil || strings.TrimSpace(kubeconfig) == "" {
		return InventoryHealth{Checked: true, Message: "cluster inventory check is not configured"}
	}
	raw, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "get", "nodes", "-o", "json")
	if err != nil {
		return InventoryHealth{Checked: true, Message: fmt.Sprintf("query Kubernetes cluster inventory: %v", err)}
	}
	var response struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			} `json:"metadata"`
			Status struct {
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(raw), &response); err != nil {
		return InventoryHealth{Checked: true, Message: fmt.Sprintf("decode Kubernetes cluster inventory: %v", err)}
	}
	if len(expected) == 0 {
		return InventoryHealth{Checked: true, Message: "authoritative cluster inventory is empty"}
	}
	seen := make(map[string]bool, len(response.Items))
	for _, observed := range response.Items {
		name, uid := strings.TrimSpace(observed.Metadata.Name), strings.TrimSpace(observed.Metadata.UID)
		if name == "" || uid == "" {
			return InventoryHealth{Checked: true, Message: "Kubernetes returned a node without name or UID"}
		}
		seen[name] = true
		var recorded *state.ClusterNode
		for i := range expected {
			if expected[i].Name == name {
				recorded = &expected[i]
				break
			}
		}
		if recorded == nil {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("Kubernetes node %q is not enrolled in the appliance cluster inventory", name)}
		}
		if strings.TrimSpace(recorded.NodeUID) == "" {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("cluster inventory node %q is missing an immutable Kubernetes UID", name)}
		}
		if recorded.NodeUID != uid {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("Kubernetes node %q UID does not match the enrolled cluster inventory", name)}
		}
		ready := false
		for _, condition := range observed.Status.Conditions {
			if condition.Type == "Ready" {
				ready = condition.Status == "True"
				break
			}
		}
		if !ready {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("Kubernetes node %q is not Ready", name)}
		}
	}
	for _, node := range expected {
		if !seen[node.Name] {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("enrolled cluster node %q is absent from Kubernetes", node.Name)}
		}
	}
	return InventoryHealth{Checked: true, Healthy: true, Message: fmt.Sprintf("%d enrolled Kubernetes node(s) are Ready with matching UIDs", len(expected))}
}

// ValidateWorkerUpgradeReadiness is the control-plane admission gate for an
// ordered cluster upgrade. Workers are upgraded locally from the signed
// bundle, then Kubernetes reports the running agent's kubelet version. The
// control plane must not advance until every enrolled worker both remains
// healthy and reports the bundle-pinned K3s version. This is deliberately a
// live observation rather than an operator acknowledgement or a copied local
// receipt, either of which could be stale.
func ValidateWorkerUpgradeReadiness(ctx context.Context, run cli.Runner, kubeconfig string, expected []state.ClusterNode, targetK3sVersion string) InventoryHealth {
	targetK3sVersion = strings.TrimSpace(targetK3sVersion)
	if targetK3sVersion == "" {
		return InventoryHealth{Checked: true, Message: "target K3s version is required for cluster upgrade readiness"}
	}
	inventory := ValidateInventory(ctx, run, kubeconfig, expected)
	if !inventory.Healthy {
		return inventory
	}
	workers := 0
	for _, node := range expected {
		if node.Role == state.NodeRoleControlPlane || node.Name == "" {
			continue
		}
		workers++
		observed, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "get", "node", node.Name, "-o", "jsonpath={.status.nodeInfo.kubeletVersion}")
		if err != nil {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("query enrolled worker %q K3s version: %v", node.Name, err)}
		}
		if strings.TrimSpace(observed) != targetK3sVersion {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("enrolled worker %q reports K3s %q; upgrade it locally to signed target %q before upgrading the control plane", node.Name, strings.TrimSpace(observed), targetK3sVersion)}
		}
	}
	return InventoryHealth{Checked: true, Healthy: true, Message: fmt.Sprintf("%d enrolled worker(s) report target K3s %s", workers, targetK3sVersion)}
}
