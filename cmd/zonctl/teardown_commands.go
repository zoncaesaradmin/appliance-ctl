package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/backup"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/teardown"
)

func runUninstall(ctx context.Context, opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	if opts.confirm == "" {
		return finish(result, "failed", 1, "uninstall: --confirm <token> is required to acknowledge this destructive operation", nil)
	}

	ops := k3s.DefaultOps()
	checks, err := teardown.Uninstall(ctx, ops, defaultK3sUnitName, installedStatePath(opts.stateDir), defaultK3sBinaryDestPath, defaultK3sConfigPath, defaultK3sUnitPath)

	reportID := "evidence-" + time.Now().UTC().Format("20060102T150405Z0700")
	if report, buildErr := evidence.BuildReport("uninstall", version, reportID, checks, time.Now()); buildErr == nil {
		if !opts.dryRun {
			if persistErr := persistEvidence(opts.stateDir, reportID, report); persistErr != nil {
				logger.Warn("failed to persist evidence report", "error", persistErr)
			}
		}
	} else {
		logger.Warn("failed to build uninstall evidence report", "error", buildErr)
	}

	if err != nil {
		logger.Error("uninstall failed", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}

	logger.Info("uninstall complete", "dataPreserved", true)
	data, _ := json.Marshal(map[string]any{"dataPreserved": true})
	result.Confirmation = &confirmation{Mode: "non-interactive", AcknowledgedDataLoss: false, Token: opts.confirm}
	return finish(result, "succeeded", 0, "uninstall complete; platform data preserved", data)
}

func runFactoryReset(ctx context.Context, opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	if opts.confirm == "" {
		return finish(result, "failed", 1, "factory-reset: --confirm <token> is required", nil)
	}
	if !opts.acknowledgeDataLoss {
		return finish(result, "failed", 1, "factory-reset: --acknowledge-data-loss is required", nil)
	}

	backupVerified := false
	if opts.backupID != "" {
		backupDir := filepath.Join(backupRootDir(opts.stateDir), opts.backupID)
		if _, err := backup.Verify(backupDir); err != nil {
			logger.Error("supplied backup failed verification", "error", err, "backupId", opts.backupID)
			return finish(result, "failed", 1, "factory-reset: supplied backup failed verification: "+err.Error(), nil)
		}
		backupVerified = true
	}
	if !backupVerified && !opts.forceDataLoss {
		return finish(result, "failed", 1, "factory-reset: requires --backup-id <verified backup> or --force-data-loss", nil)
	}

	ops := k3s.DefaultOps()
	checks, err := teardown.FactoryReset(ctx, ops, defaultK3sUnitName, installedStatePath(opts.stateDir), defaultK3sBinaryDestPath, defaultK3sConfigPath, defaultK3sUnitPath, defaultK3sDataDir, backupVerified, opts.forceDataLoss)

	reportID := "evidence-" + time.Now().UTC().Format("20060102T150405Z0700")
	if report, buildErr := evidence.BuildReport("factory-reset", version, reportID, checks, time.Now()); buildErr == nil {
		if !opts.dryRun {
			if persistErr := persistEvidence(opts.stateDir, reportID, report); persistErr != nil {
				logger.Warn("failed to persist evidence report", "error", persistErr)
			}
		}
	} else {
		logger.Warn("failed to build factory-reset evidence report", "error", buildErr)
	}

	if err != nil {
		logger.Error("factory-reset failed", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}

	logger.Info("factory-reset complete", "backupVerified", backupVerified)
	data, _ := json.Marshal(map[string]any{"dataLossAcknowledged": true, "backupVerified": backupVerified})
	result.Confirmation = &confirmation{Mode: "non-interactive", AcknowledgedDataLoss: true, Token: opts.confirm}
	return finish(result, "succeeded", 0, "factory-reset complete; all platform data removed", data)
}
