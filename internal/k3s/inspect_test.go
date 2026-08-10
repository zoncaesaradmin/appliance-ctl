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
	// controlplane in ace-system; apps + message-broker product namespaces.
	pods := "kube-system\nkube-system\nace-system\nace-apps\n"

	healthy, foreign, err := k3s.InspectCluster(context.Background(), fakeKubectl(nodes, pods, nil, nil), "/etc/rancher/k3s/k3s.yaml", "ace-system")
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

func TestInspectCluster_TreatsTraefikAsSystemNamespace(t *testing.T) {
	nodes := "node1   Ready    control-plane,master   10d   v1.30.4+k3s1\n"
	pods := "kube-system\ntraefik\nace-apps\n"

	healthy, foreign, err := k3s.InspectCluster(context.Background(), fakeKubectl(nodes, pods, nil, nil), "/etc/rancher/k3s/k3s.yaml", "ace-system")
	if err != nil {
		t.Fatal(err)
	}
	if !healthy {
		t.Error("expected the cluster to be reported healthy")
	}
	if len(foreign) != 0 {
		t.Errorf("expected no foreign namespaces when only traefik is present, got %v", foreign)
	}
}

func TestInspectCluster_DetectsForeignWorkloads(t *testing.T) {
	nodes := "node1   Ready    control-plane,master   10d   v1.30.4+k3s1\n"
	pods := "kube-system\ncustomer-app\ncustomer-app\nace-apps\n"

	_, foreign, err := k3s.InspectCluster(context.Background(), fakeKubectl(nodes, pods, nil, nil), "/etc/rancher/k3s/k3s.yaml", "ace-system")
	if err != nil {
		t.Fatal(err)
	}
	if len(foreign) != 1 || foreign[0] != "customer-app" {
		t.Errorf("expected exactly [customer-app], got %v", foreign)
	}
}

func TestInspectCluster_UnhealthyWhenNodeNotReady(t *testing.T) {
	nodes := "node1   NotReady    control-plane,master   10d   v1.30.4+k3s1\n"
	healthy, _, err := k3s.InspectCluster(context.Background(), fakeKubectl(nodes, "", nil, nil), "/etc/rancher/k3s/k3s.yaml", "ace-system")
	if err != nil {
		t.Fatal(err)
	}
	if healthy {
		t.Error("expected an unhealthy verdict when a node is NotReady")
	}
}

func TestInspectCluster_UnhealthyWhenNoNodesReported(t *testing.T) {
	healthy, _, err := k3s.InspectCluster(context.Background(), fakeKubectl("", "", nil, nil), "/etc/rancher/k3s/k3s.yaml", "ace-system")
	if err != nil {
		t.Fatal(err)
	}
	if healthy {
		t.Error("expected an unhealthy verdict when no nodes are reported")
	}
}

func TestInspectCluster_PropagatesKubectlFailure(t *testing.T) {
	_, _, err := k3s.InspectCluster(context.Background(), fakeKubectl("", "", errors.New("connection refused"), nil), "/etc/rancher/k3s/k3s.yaml", "ace-system")
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("expected the kubectl failure to propagate, got: %v", err)
	}
}

func fakeIngressRoutes(names string, err error) func(context.Context, string, ...string) (string, error) {
	return func(_ context.Context, name string, args ...string) (string, error) {
		if name != "kubectl" || !containsArg(args, "ingressroutes.traefik.io") {
			return "", errors.New("unexpected invocation")
		}
		return names, err
	}
}

func TestIngressRouteExists_UsesTraefikIOAPIGroup(t *testing.T) {
	var got []string
	run := func(_ context.Context, name string, args ...string) (string, error) {
		if name != "kubectl" {
			return "", errors.New("unexpected binary")
		}
		got = append([]string(nil), args...)
		return "controlplane", nil
	}
	present, err := k3s.IngressRouteExists(context.Background(), run, "/etc/rancher/k3s/k3s.yaml", "ace-system")
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Fatal("expected present")
	}
	if !containsArg(got, "ingressroutes.traefik.io") {
		t.Fatalf("expected fully-qualified traefik.io resource, got %v", got)
	}
	if containsArg(got, "ingressroute") {
		t.Fatalf("short name ingressroute resolves to legacy containo.us CRD; got %v", got)
	}
}

// This is the exact scenario that motivated the check: helm and K3s both
// report healthy while the chart never rendered an IngressRoute, so no
// traffic can reach the appliance pod. IngressRouteExists is what lets
// zonctl status/verify catch it.
func TestIngressRouteExists_ReportsAbsence(t *testing.T) {
	present, err := k3s.IngressRouteExists(context.Background(), fakeIngressRoutes("", nil), "/etc/rancher/k3s/k3s.yaml", "ace-system")
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Error("expected no ingress route to be reported present")
	}
}

func TestIngressRouteExists_ReportsPresence(t *testing.T) {
	present, err := k3s.IngressRouteExists(context.Background(), fakeIngressRoutes("controlplane", nil), "/etc/rancher/k3s/k3s.yaml", "ace-system")
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Error("expected the ingress route to be reported present")
	}
}

func TestIngressRouteExists_PropagatesKubectlFailure(t *testing.T) {
	_, err := k3s.IngressRouteExists(context.Background(), fakeIngressRoutes("", errors.New("connection refused")), "/etc/rancher/k3s/k3s.yaml", "ace-system")
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("expected the kubectl failure to propagate, got: %v", err)
	}
}
