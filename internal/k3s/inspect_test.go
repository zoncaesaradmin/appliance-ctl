package k3s_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
)

func fakeKubectl(nodesOut, podsOut string, nodesErr, podsErr error) func(context.Context, string, ...string) (string, error) {
	return func(_ context.Context, name string, args ...string) (string, error) {
		if name != "kubectl" {
			return "", errors.New("unexpected binary")
		}
		if containsArg(args, "nodes") {
			return nodesOut, nodesErr
		}
		if containsArg(args, "pods") {
			return podsOut, podsErr
		}
		return "", errors.New("unexpected kubectl invocation")
	}
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func TestInspectCluster_HealthyNoForeignWorkloads(t *testing.T) {
	nodes := "node1   Ready    control-plane,master   10d   v1.30.4+k3s1\n"
	pods := "kube-system\nkube-system\nzon\n"

	healthy, foreign, err := k3s.InspectCluster(context.Background(), fakeKubectl(nodes, pods, nil, nil), "/etc/rancher/k3s/k3s.yaml", "zon")
	if err != nil {
		t.Fatal(err)
	}
	if !healthy {
		t.Error("expected the cluster to be reported healthy")
	}
	if len(foreign) != 0 {
		t.Errorf("expected no foreign namespaces, got %v", foreign)
	}
}

func TestInspectCluster_DetectsForeignWorkloads(t *testing.T) {
	nodes := "node1   Ready    control-plane,master   10d   v1.30.4+k3s1\n"
	pods := "kube-system\ncustomer-app\ncustomer-app\nzon\n"

	_, foreign, err := k3s.InspectCluster(context.Background(), fakeKubectl(nodes, pods, nil, nil), "/etc/rancher/k3s/k3s.yaml", "zon")
	if err != nil {
		t.Fatal(err)
	}
	if len(foreign) != 1 || foreign[0] != "customer-app" {
		t.Errorf("expected exactly [customer-app], got %v", foreign)
	}
}

func TestInspectCluster_UnhealthyWhenNodeNotReady(t *testing.T) {
	nodes := "node1   NotReady    control-plane,master   10d   v1.30.4+k3s1\n"
	healthy, _, err := k3s.InspectCluster(context.Background(), fakeKubectl(nodes, "", nil, nil), "/etc/rancher/k3s/k3s.yaml", "zon")
	if err != nil {
		t.Fatal(err)
	}
	if healthy {
		t.Error("expected an unhealthy verdict when a node is NotReady")
	}
}

func TestInspectCluster_UnhealthyWhenNoNodesReported(t *testing.T) {
	healthy, _, err := k3s.InspectCluster(context.Background(), fakeKubectl("", "", nil, nil), "/etc/rancher/k3s/k3s.yaml", "zon")
	if err != nil {
		t.Fatal(err)
	}
	if healthy {
		t.Error("expected an unhealthy verdict when no nodes are reported")
	}
}

func TestInspectCluster_PropagatesKubectlFailure(t *testing.T) {
	_, _, err := k3s.InspectCluster(context.Background(), fakeKubectl("", "", errors.New("connection refused"), nil), "/etc/rancher/k3s/k3s.yaml", "zon")
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("expected the kubectl failure to propagate, got: %v", err)
	}
}
