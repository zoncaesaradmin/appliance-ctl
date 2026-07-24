package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/lifecycle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
	"github.com/zoncaesaradmin/appliance-ctl/internal/upgrade"
)

func runUpgrade(ctx context.Context, opts cliOptions, txn *lifecycle.Transaction, logger *slog.Logger, result commandResult) commandResult {
	installed, loadErr := state.Load(installedStatePath(opts.stateDir))
	if loadErr != nil {
		return finish(result, "failed", 1, "upgrade: "+loadErr.Error(), nil)
	}
	currentProfile := ""
	if installed != nil {
		currentProfile = installed.ApplianceProfile
	}
	effectiveProfile, profileErr := productconfig.ResolveApplianceProfile(opts.applianceProfile, currentProfile)
	if profileErr != nil {
		return finish(result, "failed", 1, "upgrade: "+profileErr.Error(), nil)
	}
	source, resolved, resolveChecks, err := resolveVerifiedInstallSource(ctx, opts, effectiveProfile)
	upgradeVersion := version
	if trimmed := strings.TrimSpace(resolved.BundleVersion); trimmed != "" {
		upgradeVersion = trimmed
	}
	result.ApplianceVersion = upgradeVersion
	if err != nil {
		logger.Error("failed to resolve upgrade source", "error", err)
		reportID := "evidence-" + txn.ID
		reportPath := ""
		if len(resolveChecks) > 0 {
			if report, buildErr := evidence.BuildReport("upgrade", upgradeVersion, reportID, resolveChecks, time.Now()); buildErr == nil {
				if !opts.dryRun {
					if persistErr := persistEvidence(opts.stateDir, reportID, report); persistErr != nil {
						logger.Warn("failed to persist evidence report", "error", persistErr)
					} else {
						reportPath = evidenceReportPath(opts.stateDir, reportID)
					}
				}
			}
		}
		return finish(result, "failed", 1, withFailureDiagnostics("upgrade: "+err.Error(), resolveChecks, reportPath), nil)
	}

	upgradeOpts := upgrade.Options{
		TargetApplianceVersion: version,
		InstalledStatePath:     installedStatePath(opts.stateDir),
		K3sConfigPath:          defaultK3sConfigPath,
		K3sUnitPath:            defaultK3sUnitPath,
		K3sBinaryDestPath:      defaultK3sBinaryDestPath,
		K3sUnitName:            defaultK3sUnitName,
		K3sDataDir:             defaultK3sDataDir,
		KubeconfigPath:         defaultKubeconfigPath,
		ApplianceProfile:       opts.applianceProfile,
		BuildCatalogPath:       opts.buildCatalogPath,
		WorkspaceRootDir:       defaultWorkspaceRootDir,
		NodeName:               opts.nodeName,
		TLSSANs:                effectiveTLSSANs(opts.nodeName),
		PreserveFailedState:    opts.preserveFailedState,
		ZonctlRealDestPath:     defaultZonctlRealPath,
		ZonctlLauncherDestPath: defaultZonctlLauncherPath,
		ChartReleaseName:       defaultChartReleaseName,
		ChartNamespace:         defaultChartNamespace,
		BackupRoot:             backupRootDir(opts.stateDir),
		TransactionID:          txn.ID,
	}

	orch := upgrade.NewOrchestrator()
	updated, checks, err := orch.Upgrade(ctx, source, upgradeOpts)

	reportID := "evidence-" + txn.ID
	reportPath := ""
	if report, buildErr := evidence.BuildReport("upgrade", upgradeVersion, reportID, checks, time.Now()); buildErr == nil {
		if !opts.dryRun {
			if persistErr := persistEvidence(opts.stateDir, reportID, report); persistErr != nil {
				logger.Warn("failed to persist evidence report", "error", persistErr)
			} else {
				reportPath = evidenceReportPath(opts.stateDir, reportID)
			}
		}
	} else {
		logger.Warn("failed to build upgrade evidence report", "error", buildErr)
	}

	if err != nil {
		logger.Error("upgrade failed", "error", err, "transactionId", txn.ID)
		status := "failed"
		if strings.Contains(err.Error(), "rolled back") {
			status = "rolled-back"
		}
		return finish(result, status, 1, withFailureDiagnostics(err.Error(), checks, reportPath), nil)
	}

	logger.Info("upgrade complete", "transactionId", txn.ID, "sourceVersion", updated.LastOperation.SourceVersion, "targetVersion", updated.LastOperation.TargetVersion)
	data, _ := json.Marshal(map[string]any{
		"sourceVersion":     updated.LastOperation.SourceVersion,
		"targetVersion":     updated.LastOperation.TargetVersion,
		"applianceProfile":  updated.ApplianceProfile,
		"rollbackPerformed": false,
	})
	return finish(result, "succeeded", 0, fmt.Sprintf("upgraded to %s with appliance profile %s", updated.InstalledVersion, updated.ApplianceProfile), data)
}
