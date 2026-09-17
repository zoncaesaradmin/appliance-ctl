package nvidia_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/nvidia"
)

func TestEnsureK3sRuntime_ConfiguresContainerdAndAppliesRuntimeClass(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "agent", "etc", "containerd", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("version = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var restarted string
	var applied string
	run := func(_ context.Context, name string, args ...string) (string, error) {
		joined := strings.Join(append([]string{name}, args...), " ")
		switch {
		case name == "nvidia-ctk" && strings.Contains(joined, "runtime configure"):
			if err := os.WriteFile(configPath, []byte("version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.nvidia]\n  runtime_type = \"io.containerd.runc.v2\"\n"), 0o644); err != nil {
				return "", err
			}
			return "", nil
		case name == "kubectl" && strings.Contains(joined, "apply -f"):
			applied = joined
			return "runtimeclass.node.k8s.io/nvidia configured", nil
		default:
			t.Fatalf("unexpected command: %s", joined)
			return "", nil
		}
	}

	err := nvidia.EnsureK3sRuntime(context.Background(), run, "/tmp/kubeconfig", configPath, "k3s.service", func(unit string) error {
		restarted = unit
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if restarted != "k3s.service" {
		t.Fatalf("restarted = %q", restarted)
	}
	if !strings.Contains(applied, "apply -f") {
		t.Fatalf("expected kubectl apply, got %q", applied)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "nvidia") {
		t.Fatalf("config missing nvidia:\n%s", data)
	}
}

func TestEnsureK3sRuntime_FailsWhenToolkitDoesNotWriteNvidia(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.toml")
	if err := os.WriteFile(configPath, []byte("version = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(_ context.Context, name string, _ ...string) (string, error) {
		if name == "nvidia-ctk" {
			return "", nil // pretend success but leave config unchanged
		}
		return "", nil
	}
	err := nvidia.EnsureK3sRuntime(context.Background(), run, "/tmp/kubeconfig", configPath, "k3s.service", func(string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "still lacks an nvidia runtime") {
		t.Fatalf("error = %v", err)
	}
}
