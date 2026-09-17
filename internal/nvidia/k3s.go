// Package nvidia configures host NVIDIA GPU access for appliance K3s.
package nvidia

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
)

const (
	// DefaultContainerdConfig is the K3s embedded containerd config path.
	DefaultContainerdConfig = "/var/lib/rancher/k3s/agent/etc/containerd/config.toml"
	// RuntimeClassName is the RuntimeClass handler/name engine pods request.
	RuntimeClassName = "nvidia"
)

// EnsureK3sRuntime wires the host NVIDIA Container Toolkit into K3s
// containerd and ensures the nvidia RuntimeClass exists. Call after K3s is
// running and before GPU inference workloads are scheduled.
//
// restart must restart the K3s unit so containerd reloads the config.
func EnsureK3sRuntime(ctx context.Context, run cli.Runner, kubeconfig, containerdConfigPath, k3sUnitName string, restart func(unitName string) error) error {
	if strings.TrimSpace(containerdConfigPath) == "" {
		containerdConfigPath = DefaultContainerdConfig
	}
	if strings.TrimSpace(k3sUnitName) == "" {
		k3sUnitName = "k3s.service"
	}
	if restart == nil {
		return fmt.Errorf("nvidia: k3s restart callback is required")
	}
	if run == nil {
		return fmt.Errorf("nvidia: command runner is required")
	}

	if err := os.MkdirAll(filepath.Dir(containerdConfigPath), 0o755); err != nil {
		return fmt.Errorf("nvidia: prepare containerd config dir: %w", err)
	}
	// Create an empty config if K3s has not written one yet; nvidia-ctk
	// merges the nvidia runtime into this file.
	if _, err := os.Stat(containerdConfigPath); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("nvidia: stat containerd config: %w", err)
		}
		if err := os.WriteFile(containerdConfigPath, []byte("version = 2\n"), 0o644); err != nil {
			return fmt.Errorf("nvidia: seed containerd config: %w", err)
		}
	}

	if _, err := run(ctx, "nvidia-ctk", "runtime", "configure",
		"--runtime=containerd",
		"--config="+containerdConfigPath,
	); err != nil {
		return fmt.Errorf("nvidia: nvidia-ctk runtime configure: %w", err)
	}

	data, err := os.ReadFile(containerdConfigPath)
	if err != nil {
		return fmt.Errorf("nvidia: read containerd config after configure: %w", err)
	}
	if !strings.Contains(strings.ToLower(string(data)), "nvidia") {
		return fmt.Errorf("nvidia: containerd config %s still lacks an nvidia runtime after nvidia-ctk configure", containerdConfigPath)
	}

	if err := restart(k3sUnitName); err != nil {
		return fmt.Errorf("nvidia: restart k3s after nvidia runtime configure: %w", err)
	}

	manifest := fmt.Sprintf(`apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: %s
handler: %s
`, RuntimeClassName, RuntimeClassName)
	tmp, err := os.CreateTemp("", "zonctl-nvidia-runtimeclass-*.yaml")
	if err != nil {
		return fmt.Errorf("nvidia: create RuntimeClass temp file: %w", err)
	}
	manifestPath := tmp.Name()
	defer func() { _ = os.Remove(manifestPath) }()
	if _, err := tmp.WriteString(manifest); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("nvidia: write RuntimeClass temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("nvidia: close RuntimeClass temp file: %w", err)
	}

	applyCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if _, err := run(applyCtx, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", manifestPath); err != nil {
		return fmt.Errorf("nvidia: apply RuntimeClass %s: %w", RuntimeClassName, err)
	}
	return nil
}
