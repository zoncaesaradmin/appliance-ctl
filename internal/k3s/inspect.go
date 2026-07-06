package k3s

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
)

// systemNamespaces are never treated as foreign workloads: they belong
// to K3s itself, not to any workload owner.
var systemNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
}

// InspectCluster queries an already-active K3s cluster via kubectl for
// node health and any foreign (non-system, non-Zon) workload
// namespaces. It never mutates the cluster — this is read-only
// diagnostic input to DecideOwnership. ownedNamespace is the platform's
// own namespace (e.g. "zon"), excluded from the foreign-namespace
// result.
func InspectCluster(ctx context.Context, run cli.Runner, kubeconfig, ownedNamespace string) (healthy bool, foreignNamespaces []string, err error) {
	nodesOut, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "get", "nodes", "--no-headers")
	if err != nil {
		return false, nil, fmt.Errorf("k3s: inspect cluster nodes: %w", err)
	}
	healthy = allNodesReady(nodesOut)

	podsOut, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "get", "pods", "--all-namespaces",
		"-o", `jsonpath={range .items[*]}{.metadata.namespace}{"\n"}{end}`)
	if err != nil {
		return healthy, nil, fmt.Errorf("k3s: inspect cluster workloads: %w", err)
	}
	foreignNamespaces = foreignNamespacesFrom(podsOut, ownedNamespace)

	return healthy, foreignNamespaces, nil
}

// allNodesReady parses `kubectl get nodes --no-headers` output (columns:
// NAME STATUS ROLES AGE VERSION) and requires at least one node, all
// reporting STATUS "Ready".
func allNodesReady(output string) bool {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return false
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[1] != "Ready" {
			return false
		}
	}
	return true
}

func foreignNamespacesFrom(output, ownedNamespace string) []string {
	seen := map[string]bool{}
	for _, ns := range strings.Fields(output) {
		if ns == "" || systemNamespaces[ns] || ns == ownedNamespace {
			continue
		}
		seen[ns] = true
	}
	out := make([]string, 0, len(seen))
	for ns := range seen {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}
