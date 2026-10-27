package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/zoncaesaradmin/appliance-ctl/internal/clustertopology"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

// requireLegacySingleHostLifecycle protects the coordinated embedded-etcd
// topology from commands that only operate on local K3s and storage state.
// The embedded-etcd receipt is explicit so old prime/worker receipts retain
// their existing behavior. A future coordinated recovery implementation can
// replace this gate with quorum-aware backup, restore, repair, and teardown.
func requireLegacySingleHostLifecycle(opts cliOptions, installed *state.InstalledState, operation string) error {
	if installed != nil && installed.Cluster != nil && installed.Cluster.DeploymentTopology == state.DeploymentTopologyEmbeddedEtcdV1 {
		// Factory reset removes this host only. A one-server receipt is the
		// whole cluster. A three-server receipt still leaves the other members
		// until the operator runs the same command on each of them.
		if operation == "factory-reset" {
			return nil
		}
		return coordinatedLifecycleError(operation)
	}

	// Peers intentionally do not receive an installed-state receipt during the
	// Kubernetes-only milestone: product charts are finalized once, from the
	// bootstrap server. Their staged receipt is nevertheless authoritative for
	// this safety boundary, otherwise a peer could uninstall a live etcd member
	// with a legacy local-host command. Factory reset is the explicit
	// data-loss path for that host.
	staged, err := clustertopology.LoadBootstrapState(filepath.Join(opts.stateDir, "cluster-bootstrap-state.json"))
	if err != nil {
		return fmt.Errorf("%s: load embedded-etcd staging receipt: %w", operation, err)
	}
	if staged != nil && staged.Topology == clustertopology.EmbeddedEtcdV1 {
		if operation == "factory-reset" {
			return nil
		}
		return coordinatedLifecycleError(operation)
	}
	return nil
}

// embeddedEtcdFactoryResetScope reports the other members a local reset does
// not touch. An empty string means this host is the only recorded member.
func embeddedEtcdFactoryResetScope(opts cliOptions, installed *state.InstalledState) string {
	if installed != nil && installed.Cluster != nil && installed.Cluster.DeploymentTopology == state.DeploymentTopologyEmbeddedEtcdV1 {
		local := strings.TrimSpace(installed.Cluster.ControlPlaneNode)
		others := make([]string, 0, len(installed.Cluster.Nodes))
		for _, node := range installed.Cluster.Nodes {
			name := strings.TrimSpace(node.Name)
			if name != "" && name != local {
				others = append(others, name)
			}
		}
		if len(others) == 0 {
			return ""
		}
		return " This host only. Repeat factory-reset on " + strings.Join(others, ", ") + "."
	}
	staged, err := clustertopology.LoadBootstrapState(filepath.Join(opts.stateDir, "cluster-bootstrap-state.json"))
	if err != nil || staged == nil || staged.Topology != clustertopology.EmbeddedEtcdV1 {
		return ""
	}
	return " This host only. Repeat factory-reset on every other embedded-etcd server."
}

func coordinatedLifecycleError(operation string) error {
	return fmt.Errorf("%s: embedded-etcd appliances require the cluster-safe coordinated lifecycle implementation; the legacy local-host command is disabled", operation)
}

// requireNoEmbeddedEtcdNodeLifecycle blocks the old expandable worker/prime
// management surface after the fixed embedded-etcd topology has been
// finalized. It is intentionally separate from requireLegacySingleHostLifecycle:
// these commands do not mutate local K3s state, but could otherwise make the
// durable appliance inventory claim that a fourth node belongs to the product.
func requireNoEmbeddedEtcdNodeLifecycle(installed *state.InstalledState, operation string) error {
	if installed != nil && installed.Cluster != nil && installed.Cluster.DeploymentTopology == state.DeploymentTopologyEmbeddedEtcdV1 {
		return fmt.Errorf("%s: adding, removing, or separately managing nodes is not supported by the fixed embedded-etcd topology", operation)
	}
	return nil
}
