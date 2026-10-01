package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/backup"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdirs"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

func backupRootDir(stateDir string) string {
	return filepath.Join(stateDir, "backups")
}

// localWorkerReceipt identifies the local, agent-only half of an enrolled
// cluster. The same commands remain usable on every node, but a worker backup
// must include its own model cache and must not pretend that cache is shared
// control-plane data.
func localWorkerReceipt(installed *state.InstalledState, nodeName string) (bool, bool) {
	if installed == nil || installed.Cluster == nil || installed.Cluster.ControlPlaneNode == nodeName {
		return false, false
	}
	for _, node := range installed.Cluster.Nodes {
		if node.Name == nodeName {
			return true, node.Role == state.NodeRoleInference
		}
	}
	return true, false
}

func runBackup(ctx context.Context, opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	installed, err := state.Load(installedStatePath(opts.stateDir))
	if err != nil {
		logger.Error("failed to load installed-state", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}
	if installed == nil {
		return finish(result, "failed", 1, "backup: nothing is installed on this host", nil)
	}

	ops := k3s.DefaultOps()
	worker, inferenceWorker := localWorkerReceipt(installed, opts.nodeName)
	var manifest *backup.Manifest
	var checks []evidence.Check
	if worker {
		modelsDir := ""
		if inferenceWorker {
			modelsDir = hostdirs.InferenceModelsDir
		}
		manifest, checks, err = backup.CreateWorker(ctx, ops, defaultK3sUnitName, defaultK3sDataDir, modelsDir, backupRootDir(opts.stateDir), installed.InstalledVersion)
	} else {
		manifest, checks, err = backup.Create(ctx, ops, defaultK3sUnitName, defaultK3sDataDir, backupRootDir(opts.stateDir), version, hostdirs.MetadataBundlesDir, installed.Components.MetadataVersion, installed.Components.MetadataDigest)
	}

	reportID := "evidence-" + time.Now().UTC().Format("20060102T150405Z0700")
	if report, buildErr := evidence.BuildReport("backup", version, reportID, checks, time.Now()); buildErr == nil {
		if !opts.dryRun {
			if persistErr := persistEvidence(opts.stateDir, reportID, report); persistErr != nil {
				logger.Warn("failed to persist evidence report", "error", persistErr)
			}
		}
	} else {
		logger.Warn("failed to build backup evidence report", "error", buildErr)
	}

	if err != nil {
		logger.Error("backup failed", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}

	var sizeBytes int64
	for _, f := range manifest.Files {
		sizeBytes += f.SizeBytes
	}
	for _, f := range manifest.PolicyFiles {
		sizeBytes += f.SizeBytes
	}
	for _, f := range manifest.ModelFiles {
		sizeBytes += f.SizeBytes
	}
	logger.Info("backup complete", "backupId", manifest.BackupID, "sizeBytes", sizeBytes)

	data, _ := json.Marshal(map[string]any{
		"backupId":        manifest.BackupID,
		"sizeBytes":       sizeBytes,
		"metadataVersion": manifest.MetadataVersion,
		"metadataDigest":  manifest.MetadataDigest,
		"nodeLocalModels": len(manifest.ModelFiles),
	})
	return finish(result, "succeeded", 0, "backup "+manifest.BackupID+" created", data)
}

func runRestore(ctx context.Context, opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	if opts.backupID == "" {
		return finish(result, "failed", 1, "restore: --backup-id is required", nil)
	}

	backupDir := filepath.Join(backupRootDir(opts.stateDir), opts.backupID)
	manifest, err := backup.LoadManifest(backupDir)
	if err != nil {
		logger.Error("failed to load backup manifest", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}

	ops := k3s.DefaultOps()
	installed, loadErr := state.Load(installedStatePath(opts.stateDir))
	if loadErr != nil || installed == nil {
		if loadErr != nil {
			return finish(result, "failed", 1, loadErr.Error(), nil)
		}
		return finish(result, "failed", 1, "restore: nothing is installed on this host", nil)
	}
	worker, inferenceWorker := localWorkerReceipt(installed, opts.nodeName)
	var checks []evidence.Check
	if worker {
		modelsDir := ""
		if inferenceWorker {
			modelsDir = hostdirs.InferenceModelsDir
		}
		checks, err = backup.RestoreWorker(ctx, ops, defaultK3sUnitName, backupDir, defaultK3sDataDir, modelsDir)
	} else {
		checks, err = backup.Restore(ctx, ops, defaultK3sUnitName, backupDir, defaultK3sDataDir, hostdirs.MetadataBundlesDir)
	}

	reportID := "evidence-" + time.Now().UTC().Format("20060102T150405Z0700")
	if report, buildErr := evidence.BuildReport("restore", version, reportID, checks, time.Now()); buildErr == nil {
		if !opts.dryRun {
			if persistErr := persistEvidence(opts.stateDir, reportID, report); persistErr != nil {
				logger.Warn("failed to persist evidence report", "error", persistErr)
			}
		}
	} else {
		logger.Warn("failed to build restore evidence report", "error", buildErr)
	}

	if err != nil {
		logger.Error("restore failed", "error", err, "backupId", opts.backupID)
		return finish(result, "failed", 1, err.Error(), nil)
	}

	logger.Info("restore complete", "backupId", manifest.BackupID)
	data, _ := json.Marshal(map[string]any{
		"backupId":        manifest.BackupID,
		"restoredVersion": manifest.ApplianceVersion,
		"metadataVersion": manifest.MetadataVersion,
		"metadataDigest":  manifest.MetadataDigest,
	})
	return finish(result, "succeeded", 0, "restored from backup "+manifest.BackupID, data)
}
