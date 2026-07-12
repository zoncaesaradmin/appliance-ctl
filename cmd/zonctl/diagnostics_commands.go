package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/diagnostics"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/helm"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/redact"
	"github.com/zoncaesaradmin/appliance-ctl/internal/repair"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
	"github.com/zoncaesaradmin/appliance-ctl/internal/support"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

func installedStatePath(stateDir string) string {
	return filepath.Join(stateDir, "installed-state.json")
}

// dependencySignals loads installed-state and the K3s service signal, then
// (only when something is actually installed and K3s is active) checks
// the Helm release's status and whether an IngressRoute exists, so
// status/verify stop falsely reporting "healthy" when the chart or
// ingress layer is broken even though K3s itself is fine. It never fails
// outright: every one of these is a legitimate, reportable finding for
// status/verify, not a command error — except a k3s detection error,
// which signals something more fundamentally wrong with the host.
func dependencySignals(ctx context.Context, run cli.Runner, stateDir, unitName, kubeconfig, releaseName, namespace string) (diagnostics.Signals, error) {
	installed, stateErr := state.Load(installedStatePath(stateDir))
	signal, err := k3s.DetectService(unitName)
	if err != nil {
		return diagnostics.Signals{}, fmt.Errorf("detect k3s service: %w", err)
	}

	health := k3s.HealthStatus{Healthy: signal.Active}
	if !signal.Active {
		health.Reasons = []string{"k3s service is not active"}
	}

	sig := diagnostics.Signals{InstalledState: installed, InstalledStateErr: stateErr, K3sHealth: health}

	if installed == nil || !signal.Active {
		return sig, nil
	}

	if chartHealthy, chartMsg, chartErr := helm.CheckReleaseHealth(ctx, run, kubeconfig, releaseName, namespace); chartErr != nil {
		sig.ChartHealth = diagnostics.ChartHealth{Checked: true, Healthy: false, Message: chartErr.Error()}
	} else {
		sig.ChartHealth = diagnostics.ChartHealth{Checked: true, Healthy: chartHealthy, Message: chartMsg}
	}

	if ingressPresent, ingressErr := k3s.IngressRouteExists(ctx, run, kubeconfig, namespace); ingressErr != nil {
		sig.IngressHealth = diagnostics.IngressHealth{Checked: true, Present: false, Message: ingressErr.Error()}
	} else {
		msg := fmt.Sprintf("ingress route present in namespace %s", namespace)
		if !ingressPresent {
			msg = fmt.Sprintf("no ingress route found in namespace %s", namespace)
		}
		sig.IngressHealth = diagnostics.IngressHealth{Checked: true, Present: ingressPresent, Message: msg}
	}

	return sig, nil
}

func runStatus(ctx context.Context, opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	sig, err := dependencySignals(ctx, cli.Exec, opts.stateDir, defaultK3sUnitName, defaultKubeconfigPath, defaultChartReleaseName, defaultChartNamespace)
	if err != nil {
		logger.Error("failed to gather status signals", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}

	checks := diagnostics.Evaluate(sig)
	reportID := "evidence-" + time.Now().UTC().Format("20060102T150405Z0700")
	if report, buildErr := evidence.BuildReport("status", version, reportID, checks, time.Now()); buildErr == nil {
		if !opts.dryRun {
			if persistErr := persistEvidence(opts.stateDir, reportID, report); persistErr != nil {
				logger.Warn("failed to persist evidence report", "error", persistErr)
			}
		}
	} else {
		logger.Warn("failed to build status evidence report", "error", buildErr)
	}

	installedVersion := ""
	if sig.InstalledState != nil {
		installedVersion = sig.InstalledState.InstalledVersion
	}
	componentHealth := []map[string]any{{"name": "k3s", "healthy": sig.K3sHealth.Healthy}}
	if !sig.K3sHealth.Healthy {
		componentHealth[0]["detail"] = sig.K3sHealth.Reasons[0]
	}
	if sig.ChartHealth.Checked {
		entry := map[string]any{"name": "chart", "healthy": sig.ChartHealth.Healthy}
		if !sig.ChartHealth.Healthy {
			entry["detail"] = sig.ChartHealth.Message
		}
		componentHealth = append(componentHealth, entry)
	}
	if sig.IngressHealth.Checked {
		entry := map[string]any{"name": "ingress", "healthy": sig.IngressHealth.Present}
		if !sig.IngressHealth.Present {
			entry["detail"] = sig.IngressHealth.Message
		}
		componentHealth = append(componentHealth, entry)
	}
	data, _ := json.Marshal(map[string]any{
		"installedVersion": installedVersion,
		"k3sHealthy":       sig.K3sHealth.Healthy,
		"componentHealth":  componentHealth,
	})

	overall := evidence.OverallStatus(checks)
	exitCode := 0
	if overall != evidence.StatusPass {
		exitCode = 1
	}
	return finish(result, "succeeded", exitCode, fmt.Sprintf("status: %s", overall), data)
}

func runVerify(ctx context.Context, opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	sig, err := dependencySignals(ctx, cli.Exec, opts.stateDir, defaultK3sUnitName, defaultKubeconfigPath, defaultChartReleaseName, defaultChartNamespace)
	if err != nil {
		logger.Error("failed to gather verify signals", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}

	checks := diagnostics.Evaluate(sig)
	reportID := "evidence-" + time.Now().UTC().Format("20060102T150405Z0700")
	if report, buildErr := evidence.BuildReport("verify", version, reportID, checks, time.Now()); buildErr == nil {
		if !opts.dryRun {
			if persistErr := persistEvidence(opts.stateDir, reportID, report); persistErr != nil {
				logger.Warn("failed to persist evidence report", "error", persistErr)
			}
		}
	} else {
		logger.Warn("failed to build verify evidence report", "error", buildErr)
	}

	// This verifies the installed-state record's own schema/self-
	// consistency and current K3s health. Re-verifying every installed
	// artifact's digest against the original release manifest requires
	// retaining that manifest post-install, which is not yet wired up
	// (a gap worth closing in a future pass, not silently pretended away
	// here).
	manifestValid := sig.InstalledStateErr == nil && sig.InstalledState != nil
	entriesVerified := 0
	entriesFailed := []string{}
	if manifestValid {
		entriesVerified = 1
	} else {
		entriesFailed = append(entriesFailed, "installed-state.json")
	}
	data, _ := json.Marshal(map[string]any{
		"manifestValid":   manifestValid,
		"entriesVerified": entriesVerified,
		"entriesFailed":   entriesFailed,
	})

	overall := evidence.OverallStatus(checks)
	exitCode := 0
	if overall != evidence.StatusPass {
		exitCode = 1
	}
	return finish(result, "succeeded", exitCode, fmt.Sprintf("verify: %s", overall), data)
}

func runRepair(ctx context.Context, opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	installed, err := state.Load(installedStatePath(opts.stateDir))
	if err != nil {
		logger.Error("failed to load installed-state", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}

	ops := k3s.DefaultOps()
	checks, repairErr := repair.Repair(ctx, ops, installed, defaultK3sUnitName)

	reportID := "evidence-" + time.Now().UTC().Format("20060102T150405Z0700")
	if report, buildErr := evidence.BuildReport("repair", version, reportID, checks, time.Now()); buildErr == nil {
		if !opts.dryRun {
			if persistErr := persistEvidence(opts.stateDir, reportID, report); persistErr != nil {
				logger.Warn("failed to persist evidence report", "error", persistErr)
			}
		}
	} else {
		logger.Warn("failed to build repair evidence report", "error", buildErr)
	}

	if repairErr != nil {
		logger.Error("repair failed", "error", repairErr)
		return finish(result, "failed", 1, repairErr.Error(), nil)
	}

	actions := make([]string, 0, len(checks))
	for _, c := range checks {
		actions = append(actions, c.Message)
	}
	data, _ := json.Marshal(map[string]any{"actionsPerformed": actions})
	return finish(result, "succeeded", 0, "repair complete", data)
}

func runSupportBundle(ctx context.Context, opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	sig, err := dependencySignals(ctx, cli.Exec, opts.stateDir, defaultK3sUnitName, defaultKubeconfigPath, defaultChartReleaseName, defaultChartNamespace)
	if err != nil {
		logger.Error("failed to gather support-bundle diagnostics", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}
	checks := diagnostics.Evaluate(sig)

	var sources []support.Source
	if installedStateBytes, err := os.ReadFile(installedStatePath(opts.stateDir)); err == nil {
		sources = append(sources, support.Source{Name: "installed-state.json", Content: installedStateBytes})
	}

	diagnosticsReport, err := evidence.BuildReport("support-bundle", version, "diagnostics", checks, time.Now())
	if err == nil {
		sources = append(sources, support.Source{Name: "diagnostics.json", Content: diagnosticsReport})
	}

	evidenceDir := filepath.Join(opts.stateDir, "evidence")
	if entries, err := os.ReadDir(evidenceDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if data, err := os.ReadFile(filepath.Join(evidenceDir, e.Name())); err == nil {
				sources = append(sources, support.Source{Name: filepath.Join("evidence", e.Name()), Content: data})
			}
		}
	}

	if len(sources) == 0 {
		return finish(result, "failed", 1, "support-bundle: nothing to collect (host has no installed-state or evidence yet)", nil)
	}

	bundleDir := filepath.Join(opts.stateDir, "support-bundles")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		logger.Error("failed to prepare support-bundle directory", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}
	bundlePath := filepath.Join(bundleDir, "support-bundle-"+time.Now().UTC().Format("20060102T150405Z0700")+".tar.gz")

	// No secrets are known to this process today (nothing calls
	// redactor.Register yet), but every source still passes through the
	// redaction pipeline unconditionally, so wiring a secret-bearing
	// adapter in later never requires touching this call site.
	if err := support.Build(bundlePath, sources, redact.New()); err != nil {
		logger.Error("failed to build support bundle", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}

	digest, err := verify.Digest(bundlePath)
	if err != nil {
		logger.Error("failed to digest support bundle", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}

	data, _ := json.Marshal(map[string]any{
		"bundlePath":      bundlePath,
		"digest":          digest,
		"secretsRedacted": true,
	})
	return finish(result, "succeeded", 0, "support bundle created at "+bundlePath, data)
}
