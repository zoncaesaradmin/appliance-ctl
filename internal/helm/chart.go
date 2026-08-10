package helm

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
)

// ChartRelease describes one Helm release to apply from bundle-local
// artifacts: an exact chart archive and schema-validated values file.
type ChartRelease struct {
	Name       string
	ChartPath  string
	Namespace  string
	ValuesPath string
	// NamespaceLabels are applied via kubectl before Helm runs so PSA
	// exceptions exist before the first pod is admitted.
	NamespaceLabels map[string]string
}

// InstallOrUpgrade applies rel via `helm upgrade --install`, which is
// idempotent by construction: a fresh cluster gets an install, an
// existing release gets an upgrade, and re-running it with unchanged
// inputs is a safe no-op. It deliberately does not use Helm --wait: runtime
// services must reconnect asynchronously instead of blocking unrelated
// installs.
func (a *Applier) InstallOrUpgrade(ctx context.Context, rel ChartRelease) (evidence.Check, error) {
	check := evidence.Check{
		ID:              "helm-release-" + evidence.SanitizeIDSegment(rel.Name),
		Category:        "chart",
		Timestamp:       time.Now().UTC(),
		Idempotent:      true,
		SecretsRedacted: true,
	}

	requiredPaths := []string{rel.ChartPath}
	if strings.TrimSpace(rel.ValuesPath) != "" {
		requiredPaths = append(requiredPaths, rel.ValuesPath)
	}
	for _, path := range requiredPaths {
		if _, err := os.Stat(path); err != nil {
			check.Status = evidence.StatusFail
			check.Message = fmt.Sprintf("required artifact missing: %v", err)
			return check, fmt.Errorf("helm: %w", err)
		}
	}

	if err := EnsureNamespace(ctx, a.Run, a.Kubeconfig, rel.Namespace, rel.NamespaceLabels); err != nil {
		check.Status = evidence.StatusFail
		check.Message = err.Error()
		return check, err
	}

	args := []string{
		"--kubeconfig", a.Kubeconfig,
		"upgrade", "--install", rel.Name, rel.ChartPath,
		"--namespace", rel.Namespace,
	}
	if strings.TrimSpace(rel.ValuesPath) != "" {
		args = append(args, "--values", rel.ValuesPath)
	}
	if _, err := a.Run(ctx, "helm", args...); err != nil {
		check.Status = evidence.StatusFail
		check.Message = err.Error()
		return check, fmt.Errorf("helm: install/upgrade %s: %w", rel.Name, err)
	}

	check.Status = evidence.StatusPass
	check.Message = fmt.Sprintf("release %s applied from %s", rel.Name, rel.ChartPath)
	return check, nil
}

// Rollback undoes a failed InstallOrUpgrade. A release that never
// existed before this run (wasFreshInstall) is uninstalled outright; an
// existing release that failed to upgrade is rolled back to its prior
// revision instead, per "the declared N-1 rollback."
func (a *Applier) Rollback(ctx context.Context, releaseName string, wasFreshInstall bool) error {
	return a.RollbackInNamespace(ctx, releaseName, "", wasFreshInstall)
}

// RollbackInNamespace rolls back or removes a release in its owning namespace.
func (a *Applier) RollbackInNamespace(ctx context.Context, releaseName, namespace string, wasFreshInstall bool) error {
	if wasFreshInstall {
		return a.UninstallInNamespace(ctx, releaseName, namespace)
	}

	args := []string{"--kubeconfig", a.Kubeconfig, "rollback", releaseName}
	if strings.TrimSpace(namespace) != "" {
		args = append(args, "--namespace", namespace)
	}
	if _, err := a.Run(ctx, "helm", args...); err != nil {
		if helmReleaseMissing(err) {
			return nil
		}
		return fmt.Errorf("helm: rollback %s: %w", releaseName, err)
	}
	return nil
}

// Uninstall removes a Helm release and tolerates missing-release results so
// callers can use it for capability cleanup and failed fresh installs.
func (a *Applier) Uninstall(ctx context.Context, releaseName string) error {
	return a.UninstallInNamespace(ctx, releaseName, "")
}

// UninstallInNamespace removes a release from its owning namespace.
func (a *Applier) UninstallInNamespace(ctx context.Context, releaseName, namespace string) error {
	args := []string{"--kubeconfig", a.Kubeconfig, "uninstall", releaseName}
	if strings.TrimSpace(namespace) != "" {
		args = append(args, "--namespace", namespace)
	}
	if _, err := a.Run(ctx, "helm", args...); err != nil {
		if helmReleaseMissing(err) {
			return nil
		}
		return fmt.Errorf("helm: uninstall %s: %w", releaseName, err)
	}
	return nil
}

func helmReleaseMissing(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "release: not found") ||
		strings.Contains(msg, "release not loaded") ||
		strings.Contains(msg, "has no deployed releases") ||
		strings.Contains(msg, "release: no deployed releases")
}
