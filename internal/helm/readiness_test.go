package helm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type readinessFakeCLI struct {
	calls                  []string
	nodePolls              int
	storageClassPolls      int
	provisionerPolls       int
	nodeReadyAfter         int
	storageClassReadyAfter int
	provisionerReadyAfter  int
}

func (f *readinessFakeCLI) Run(_ context.Context, name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)

	switch {
	case name == "kubectl" && contains(args, "get") && contains(args, "nodes"):
		f.nodePolls++
		if f.nodePolls < f.nodeReadyAfter {
			return "appliance-node   NotReady   control-plane   1m   v1.30.4+k3s1\n", nil
		}
		return "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n", nil
	case name == "kubectl" && contains(args, "get") && contains(args, "storageclass"):
		f.storageClassPolls++
		if f.storageClassPolls < f.storageClassReadyAfter {
			return "", fmt.Errorf("simulated storage class not found")
		}
		return "storageclass.storage.k8s.io/local-path", nil
	case name == "kubectl" && contains(args, "get") && contains(args, "deployment") && contains(args, "local-path-provisioner"):
		f.provisionerPolls++
		if f.provisionerPolls < f.provisionerReadyAfter {
			return "0", nil
		}
		return "1", nil
	default:
		return "", nil
	}
}

func TestEnsureClusterBaseline_WaitsForNodeAndLocalPathProvisioner(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("persistence:\n  enabled: true\n  storageClassName: local-path\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	fake := &readinessFakeCLI{
		nodeReadyAfter:         2,
		storageClassReadyAfter: 2,
		provisionerReadyAfter:  2,
	}
	checks, err := EnsureClusterBaseline(context.Background(), fake.Run, "kubeconfig", valuesPath)
	if err != nil {
		t.Fatalf("expected readiness checks to eventually pass, got: %v", err)
	}
	if len(checks) != 3 {
		t.Fatalf("expected 3 readiness checks, got %d", len(checks))
	}
	if fake.nodePolls < 2 || fake.storageClassPolls < 2 || fake.provisionerPolls < 2 {
		t.Fatalf("expected retries across readiness checks, got polls nodes=%d storage=%d provisioner=%d", fake.nodePolls, fake.storageClassPolls, fake.provisionerPolls)
	}
}

func TestEnsureClusterBaseline_SkipsStorageChecksWhenPersistenceDisabled(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("persistence:\n  enabled: false\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	fake := &readinessFakeCLI{
		nodeReadyAfter:         1,
		storageClassReadyAfter: 99,
		provisionerReadyAfter:  99,
	}
	checks, err := EnsureClusterBaseline(context.Background(), fake.Run, "kubeconfig", valuesPath)
	if err != nil {
		t.Fatalf("expected readiness checks to pass, got: %v", err)
	}
	if len(checks) != 1 {
		t.Fatalf("expected only node readiness check, got %d", len(checks))
	}
	if fake.storageClassPolls != 0 || fake.provisionerPolls != 0 {
		t.Fatalf("expected storage-related checks to be skipped, got polls storage=%d provisioner=%d", fake.storageClassPolls, fake.provisionerPolls)
	}
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
