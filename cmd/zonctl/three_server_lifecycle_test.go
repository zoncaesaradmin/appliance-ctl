package main

import (
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

func TestRequireNoThreeServerNodeLifecycleRejectsExpandableNodeCommands(t *testing.T) {
	installed := &state.InstalledState{Cluster: &state.Cluster{DeploymentTopology: state.DeploymentTopologyThreeServerEtcdV1}}
	for _, operation := range []string{"cluster-node-register", "cluster-node-remove", "cluster-inference-deploy"} {
		if err := requireNoThreeServerNodeLifecycle(installed, operation); err == nil || !strings.Contains(err.Error(), "not supported by the fixed three-server") {
			t.Fatalf("%s was not rejected: %v", operation, err)
		}
	}
	if err := requireNoThreeServerNodeLifecycle(&state.InstalledState{Cluster: &state.Cluster{}}, "cluster-node-register"); err != nil {
		t.Fatalf("legacy node command unexpectedly rejected: %v", err)
	}
}
