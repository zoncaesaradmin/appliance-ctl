package main

import (
	"fmt"
	"path/filepath"

	"github.com/zoncaesaradmin/appliance-ctl/internal/clustertopology"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

// requireLegacySingleHostLifecycle protects the coordinated embedded-etcd
// topology from commands that only operate on local K3s and storage state.
// The three-server receipt is explicit so old prime/worker receipts retain
// their existing behavior. A future coordinated recovery implementation can
// replace this gate with quorum-aware backup, restore, repair, and teardown.
func requireLegacySingleHostLifecycle(opts cliOptions, installed *state.InstalledState, operation string) error {
	if installed != nil && installed.Cluster != nil && installed.Cluster.DeploymentTopology == state.DeploymentTopologyThreeServerEtcdV1 {
		return coordinatedLifecycleError(operation)
	}

	// Peers intentionally do not receive an installed-state receipt during the
	// Kubernetes-only milestone: product charts are finalized once, from the
	// bootstrap server. Their staged receipt is nevertheless authoritative for
	// this safety boundary, otherwise a peer could tear down a live etcd member
	// with a legacy local-host command.
	staged, err := clustertopology.LoadBootstrapState(filepath.Join(opts.stateDir, "cluster-bootstrap-state.json"))
	if err != nil {
		return fmt.Errorf("%s: load three-server staging receipt: %w", operation, err)
	}
	if staged != nil && staged.Topology == clustertopology.ThreeServerEtcdV1 {
		return coordinatedLifecycleError(operation)
	}
	return nil
}

func coordinatedLifecycleError(operation string) error {
	return fmt.Errorf("%s: three-server embedded-etcd appliances require the cluster-safe coordinated lifecycle implementation; the legacy local-host command is disabled", operation)
}

// requireNoThreeServerNodeLifecycle blocks the old expandable worker/prime
// management surface after the fixed three-server topology has been
// finalized. It is intentionally separate from requireLegacySingleHostLifecycle:
// these commands do not mutate local K3s state, but could otherwise make the
// durable appliance inventory claim that a fourth node belongs to the product.
func requireNoThreeServerNodeLifecycle(installed *state.InstalledState, operation string) error {
	if installed != nil && installed.Cluster != nil && installed.Cluster.DeploymentTopology == state.DeploymentTopologyThreeServerEtcdV1 {
		return fmt.Errorf("%s: adding, removing, or separately managing nodes is not supported by the fixed three-server embedded-etcd topology", operation)
	}
	return nil
}
