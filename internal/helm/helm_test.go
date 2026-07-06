package helm_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/helm"
)

// fakeCLI simulates kubectl/helm invocations without a real cluster,
// recording every call for ordering/idempotency/rollback assertions.
type fakeCLI struct {
	failApply    bool
	failUpgrade  bool
	failRollback bool
	calls        [][]string
}

func (f *fakeCLI) Run(_ context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))

	switch {
	case name == "kubectl" && contains(args, "apply"):
		if f.failApply {
			return "", errors.New("simulated apply failure")
		}
		return "", nil
	case name == "helm" && contains(args, "upgrade"):
		if f.failUpgrade {
			return "", errors.New("simulated upgrade failure")
		}
		return "", nil
	case name == "helm" && (contains(args, "rollback") || contains(args, "uninstall")):
		if f.failRollback {
			return "", errors.New("simulated rollback failure")
		}
		return "", nil
	}
	return "", fmt.Errorf("unrecognized invocation: %s %v", name, args)
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func joinCall(call []string) string { return strings.Join(call, " ") }

func TestApplyCRDs_Success(t *testing.T) {
	dir := t.TempDir()
	crdDir := filepath.Join(dir, "crds")
	if err := os.MkdirAll(crdDir, 0o750); err != nil {
		t.Fatal(err)
	}

	fake := &fakeCLI{}
	a := &helm.Applier{Run: fake.Run, Kubeconfig: "/etc/rancher/k3s/k3s.yaml"}

	check, err := a.ApplyCRDs(context.Background(), crdDir)
	if err != nil {
		t.Fatal(err)
	}
	if check.Status != evidence.StatusPass {
		t.Errorf("expected pass, got %s: %s", check.Status, check.Message)
	}
}

// Missing artifact: the manifest references a CRD directory that was
// never delivered in the bundle.
func TestApplyCRDs_MissingDirectoryFailsClosed(t *testing.T) {
	fake := &fakeCLI{}
	a := &helm.Applier{Run: fake.Run, Kubeconfig: "kubeconfig"}

	missing := filepath.Join(t.TempDir(), "never-delivered-crds")
	if _, err := a.ApplyCRDs(context.Background(), missing); err == nil {
		t.Fatal("expected missing CRD directory to fail")
	}
	if len(fake.calls) != 0 {
		t.Errorf("expected no kubectl invocation for a missing directory, got %v", fake.calls)
	}
}

func sampleRelease(t *testing.T, dir string) helm.ChartRelease {
	t.Helper()
	chartPath := filepath.Join(dir, "appliance-chart-2.4.0.tgz")
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(chartPath, []byte("fake chart bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(valuesPath, []byte("replicaCount: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return helm.ChartRelease{Name: "appliance", ChartPath: chartPath, Namespace: "appliance", ValuesPath: valuesPath}
}

// Idempotency by construction: the wrapper must always use
// `helm upgrade --install`, never a bare `helm install`, so re-running it
// against an existing release is always safe.
func TestInstallOrUpgrade_UsesUpgradeInstall(t *testing.T) {
	dir := t.TempDir()
	rel := sampleRelease(t, dir)

	fake := &fakeCLI{}
	a := &helm.Applier{Run: fake.Run, Kubeconfig: "kubeconfig"}

	check, err := a.InstallOrUpgrade(context.Background(), rel)
	if err != nil {
		t.Fatal(err)
	}
	if check.Status != evidence.StatusPass {
		t.Errorf("expected pass, got %s: %s", check.Status, check.Message)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("expected exactly one helm invocation, got %v", fake.calls)
	}
	call := joinCall(fake.calls[0])
	if !strings.Contains(call, "upgrade --install") {
		t.Errorf("expected an idempotent `upgrade --install` invocation, got: %s", call)
	}
}

// Missing artifact: chart or values file absent from the bundle.
func TestInstallOrUpgrade_MissingChartFailsClosed(t *testing.T) {
	dir := t.TempDir()
	rel := sampleRelease(t, dir)
	rel.ChartPath = filepath.Join(dir, "never-delivered.tgz")

	fake := &fakeCLI{}
	a := &helm.Applier{Run: fake.Run, Kubeconfig: "kubeconfig"}

	if _, err := a.InstallOrUpgrade(context.Background(), rel); err == nil {
		t.Fatal("expected missing chart to fail")
	}
	if len(fake.calls) != 0 {
		t.Errorf("expected no helm invocation for a missing chart, got %v", fake.calls)
	}
}

// Rollback: a fresh install that failed must be uninstalled; a failed
// upgrade of an existing release must roll back to its prior revision.
func TestApplier_Rollback(t *testing.T) {
	fake := &fakeCLI{}
	a := &helm.Applier{Run: fake.Run, Kubeconfig: "kubeconfig"}

	if err := a.Rollback(context.Background(), "appliance", true); err != nil {
		t.Fatal(err)
	}
	if !contains(fake.calls[len(fake.calls)-1], "uninstall") {
		t.Errorf("expected a fresh-install failure to uninstall, got %v", fake.calls)
	}

	if err := a.Rollback(context.Background(), "appliance", false); err != nil {
		t.Fatal(err)
	}
	if !contains(fake.calls[len(fake.calls)-1], "rollback") {
		t.Errorf("expected an upgrade failure to roll back, got %v", fake.calls)
	}
}

func TestApplier_RollbackFailurePropagates(t *testing.T) {
	fake := &fakeCLI{failRollback: true}
	a := &helm.Applier{Run: fake.Run, Kubeconfig: "kubeconfig"}

	if err := a.Rollback(context.Background(), "appliance", true); err == nil {
		t.Error("expected simulated rollback failure to propagate")
	}
}

// Offline regression: none of this package's own Go code should ever
// resolve a hostname; every operation runs against local files and the
// local K3s API server via the (faked here) CLI.
func TestHelm_RequiresNoNetworkAccess(t *testing.T) {
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("network access is not permitted in this test")
		},
	}
	t.Cleanup(func() { net.DefaultResolver = original })

	dir := t.TempDir()
	crdDir := filepath.Join(dir, "crds")
	if err := os.MkdirAll(crdDir, 0o750); err != nil {
		t.Fatal(err)
	}
	rel := sampleRelease(t, dir)

	fake := &fakeCLI{}
	a := &helm.Applier{Run: fake.Run, Kubeconfig: "kubeconfig"}

	if _, err := a.ApplyCRDs(context.Background(), crdDir); err != nil {
		t.Fatalf("ApplyCRDs should succeed offline: %v", err)
	}
	if _, err := a.InstallOrUpgrade(context.Background(), rel); err != nil {
		t.Fatalf("InstallOrUpgrade should succeed offline: %v", err)
	}
	if err := a.Rollback(context.Background(), rel.Name, true); err != nil {
		t.Fatalf("Rollback should succeed offline: %v", err)
	}
}
