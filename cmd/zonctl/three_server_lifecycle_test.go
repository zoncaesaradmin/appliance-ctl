package main

import (
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

func TestFactoryResetAllowsOnlySingleNodeEmbeddedEtcd(t *testing.T) {
	single := &state.InstalledState{Cluster: &state.Cluster{
		DeploymentTopology: state.DeploymentTopologyEmbeddedEtcdV1,
		ControlPlaneNode:   "192-168-1-153",
		Nodes:              []state.ClusterNode{{ID: "192-168-1-153", Name: "192-168-1-153", Role: state.NodeRoleControlPlane}},
	}}
	if err := requireLegacySingleHostLifecycle(cliOptions{}, single, "factory-reset"); err != nil {
		t.Fatalf("single-node factory-reset rejected: %v", err)
	}
	if err := requireLegacySingleHostLifecycle(cliOptions{}, single, "uninstall"); err == nil || !strings.Contains(err.Error(), "cluster-safe coordinated lifecycle") {
		t.Fatalf("single-node uninstall was allowed: %v", err)
	}
	multi := &state.InstalledState{Cluster: &state.Cluster{
		DeploymentTopology: state.DeploymentTopologyEmbeddedEtcdV1,
		ControlPlaneNode:   "server-a",
		Nodes: []state.ClusterNode{
			{Name: "server-a"}, {Name: "server-b"}, {Name: "server-c"},
		},
	}}
	if err := requireLegacySingleHostLifecycle(cliOptions{}, multi, "factory-reset"); err != nil {
		t.Fatalf("three-server factory-reset rejected: %v", err)
	}
	if note := embeddedEtcdFactoryResetScope(cliOptions{}, multi); note != " This host only. Repeat factory-reset on server-b, server-c." {
		t.Fatalf("three-server reset scope = %q", note)
	}
	if note := embeddedEtcdFactoryResetScope(cliOptions{}, single); note != "" {
		t.Fatalf("single-node reset scope = %q", note)
	}
}

func TestRequireNoEmbeddedEtcdNodeLifecycleRejectsExpandableNodeCommands(t *testing.T) {
	installed := &state.InstalledState{Cluster: &state.Cluster{DeploymentTopology: state.DeploymentTopologyEmbeddedEtcdV1}}
	for _, operation := range []string{"cluster-node-register", "cluster-node-remove", "cluster-inference-deploy"} {
		if err := requireNoEmbeddedEtcdNodeLifecycle(installed, operation); err == nil || !strings.Contains(err.Error(), "not supported by the fixed embedded-etcd") {
			t.Fatalf("%s was not rejected: %v", operation, err)
		}
	}
	if err := requireNoEmbeddedEtcdNodeLifecycle(&state.InstalledState{Cluster: &state.Cluster{}}, "cluster-node-register"); err != nil {
		t.Fatalf("legacy node command unexpectedly rejected: %v", err)
	}
}
