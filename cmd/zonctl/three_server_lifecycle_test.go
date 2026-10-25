package main

import (
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

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
