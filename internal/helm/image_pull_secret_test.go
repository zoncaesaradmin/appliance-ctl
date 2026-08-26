package helm_test

import (
	"context"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/helm"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
)

func TestEnsureImagePullSecretsCreatesInAllProductNamespaces(t *testing.T) {
	var calls []string
	run := cli.Runner(func(_ context.Context, name string, args ...string) (string, error) {
		joined := name + " " + strings.Join(args, " ")
		calls = append(calls, joined)
		if strings.Contains(joined, "get serviceaccount -o jsonpath") {
			return "default\nworkflow-controller\n", nil
		}
		if strings.Contains(joined, "get serviceaccount default") {
			return "default", nil
		}
		if strings.Contains(joined, "get namespace") {
			return "Active", nil
		}
		return "", nil
	})

	cfg := k3s.RegistriesConfig{
		Registry:  "192.168.1.153",
		Username:  "admin",
		Password:  "token",
		TLSVerify: false,
	}
	namespaces := productconfig.ProductNamespaces("ace-system")
	prepared, err := helm.EnsureImagePullSecrets(context.Background(), run, "/kubeconfig", cfg, namespaces...)
	if err != nil {
		t.Fatalf("EnsureImagePullSecrets: %v", err)
	}
	if len(prepared.Checks) != 1 {
		t.Fatalf("expected one check, got %+v", prepared.Checks)
	}

	for _, ns := range namespaces {
		var create, patchDefault, patchController bool
		for _, call := range calls {
			if strings.Contains(call, "create secret generic "+helm.ImagePullSecretName) && strings.Contains(call, ns) {
				create = true
			}
			if strings.Contains(call, "patch serviceaccount default") && strings.Contains(call, ns) {
				patchDefault = true
			}
			if strings.Contains(call, "patch serviceaccount workflow-controller") && strings.Contains(call, ns) {
				patchController = true
			}
		}
		if !create {
			t.Fatalf("expected secret create in %s; calls=%v", ns, calls)
		}
		if !patchDefault || !patchController {
			t.Fatalf("expected SA patches in %s (default+workflow-controller); calls=%v", ns, calls)
		}
	}
	// Must not touch kube-system.
	for _, call := range calls {
		if strings.Contains(call, "kube-system") {
			t.Fatalf("must not mutate kube-system: %s", call)
		}
	}
}

func TestProductNamespacesExcludesSystemNamespaces(t *testing.T) {
	got := productconfig.ProductNamespaces("ace-system")
	want := map[string]bool{
		"ace-system":       true,
		"ace-apps":         true,
		"apps":             true,
		"artifacts":        true,
		"dns":              true,
		"inference":        true,
		"workflows":        true,
		"appliance-builds": true,
	}
	if len(got) != len(want) {
		t.Fatalf("ProductNamespaces = %v", got)
	}
	for _, ns := range got {
		if !want[ns] {
			t.Fatalf("unexpected namespace %q", ns)
		}
	}
}

func TestEnsureImagePullSecretsSkippedWhenRegistryEmpty(t *testing.T) {
	run := cli.Runner(func(context.Context, string, ...string) (string, error) {
		t.Fatal("runner must not be called when registry empty")
		return "", nil
	})
	prepared, err := helm.EnsureImagePullSecrets(context.Background(), run, "/kubeconfig", k3s.RegistriesConfig{}, "ace-apps")
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Checks) != 1 {
		t.Fatalf("expected one check, got %d", len(prepared.Checks))
	}
	if prepared.Checks[0].Status != evidence.StatusSkipped {
		t.Fatalf("want skipped, got %q", prepared.Checks[0].Status)
	}
}
