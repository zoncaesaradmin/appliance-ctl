package helm_test

import (
	"context"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/helm"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostagent"
)

func TestEnsureTraefikManagementExternalIPs_AddsMissingIP(t *testing.T) {
	var patched string
	run := func(_ context.Context, name string, args ...string) (string, error) {
		if name != "kubectl" {
			t.Fatalf("unexpected binary %q", name)
		}
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "get svc traefik") {
			return `{"spec":{"externalIPs":null}}`, nil
		}
		if strings.Contains(joined, "patch svc traefik") {
			patched = joined
			return `service/traefik patched`, nil
		}
		t.Fatalf("unexpected kubectl args: %v", args)
		return "", nil
	}

	check, err := helm.EnsureTraefikManagementExternalIPs(context.Background(), run, "/tmp/kubeconfig")
	if err != nil {
		t.Fatalf("EnsureTraefikManagementExternalIPs: %v", err)
	}
	if check.Status != evidence.StatusPass {
		t.Fatalf("check status = %q message=%q, want pass", check.Status, check.Message)
	}
	if !strings.Contains(patched, hostagent.WifiAPManagementAddress) {
		t.Fatalf("patch did not include management IP: %q", patched)
	}
	if !strings.Contains(patched, `"externalIPs"`) {
		t.Fatalf("patch missing externalIPs field: %q", patched)
	}
}

func TestEnsureTraefikManagementExternalIPs_IdempotentWhenPresent(t *testing.T) {
	patchCount := 0
	run := func(_ context.Context, name string, args ...string) (string, error) {
		if name != "kubectl" {
			t.Fatalf("unexpected binary %q", name)
		}
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "get svc traefik") {
			return `{"spec":{"externalIPs":["` + hostagent.WifiAPManagementAddress + `"]}}`, nil
		}
		if strings.Contains(joined, "patch svc traefik") {
			patchCount++
			return `service/traefik patched`, nil
		}
		t.Fatalf("unexpected kubectl args: %v", args)
		return "", nil
	}

	check, err := helm.EnsureTraefikManagementExternalIPs(context.Background(), run, "/tmp/kubeconfig")
	if err != nil {
		t.Fatalf("EnsureTraefikManagementExternalIPs: %v", err)
	}
	if check.Status != evidence.StatusPass {
		t.Fatalf("check status = %q, want pass", check.Status)
	}
	if patchCount != 0 {
		t.Fatalf("expected no patch when IP already present, got %d", patchCount)
	}
}
