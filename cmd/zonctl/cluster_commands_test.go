package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestRemoveNodeFromRoutingRegistryWithdrawsOnlyTargetNode(t *testing.T) {
	raw := []byte(`{"instances":{"node-a":{"nodeRef":"gpu-a","models":["org/a"]},"node-b":{"nodeRef":"gpu-b","models":["org/b"]}},"bindings":{"org/a":{"instanceId":"node-a"},"org/b":{"instanceId":"node-b"}}}`)
	updated, changed, err := removeNodeFromRoutingRegistry(raw, "gpu-a")
	if err != nil || !changed {
		t.Fatalf("withdraw = changed=%v err=%v", changed, err)
	}
	var registry routingRegistryJSON
	if err := json.Unmarshal(updated, &registry); err != nil {
		t.Fatal(err)
	}
	if len(registry.Instances) != 1 || registry.Instances["node-b"].NodeRef != "gpu-b" {
		t.Fatalf("instances = %#v", registry.Instances)
	}
	if len(registry.Bindings) != 1 {
		t.Fatalf("bindings = %#v", registry.Bindings)
	}
	if _, ok := registry.Bindings["org/a"]; ok {
		t.Fatal("withdrawn model binding retained")
	}
}

func TestClusterInferenceDeployDryRunNeedsOnlyNodeName(t *testing.T) {
	result := runClusterInferenceDeploy(context.Background(), cliOptions{dryRun: true, workerName: "gpu-worker-1"}, slog.Default(), commandResult{Command: "cluster-inference-deploy"})
	if result.Status != "succeeded" {
		t.Fatalf("dry-run result = %+v", result)
	}
}

func TestValidateRegisteredNodeUID(t *testing.T) {
	if err := validateRegisteredNodeUID("uid-a", "uid-a"); err != nil {
		t.Fatal(err)
	}
	if err := validateRegisteredNodeUID("uid-a", "uid-b"); err == nil {
		t.Fatal("mismatched Kubernetes node UID was accepted")
	}
}
