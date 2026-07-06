package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/host"
	"github.com/zoncaesaradmin/appliance-ctl/internal/install"
	"github.com/zoncaesaradmin/appliance-ctl/internal/lifecycle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/manifest"
	"github.com/zoncaesaradmin/appliance-ctl/internal/preflight"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

// commandResult is a command-result.v1-schema document. Data carries the
// command-specific payload (shape depends on Command); it is omitted
// entirely for commands whose bodies are still stubs.
type commandResult struct {
	SchemaVersion    int             `json:"schemaVersion"`
	Command          string          `json:"command"`
	ApplianceVersion string          `json:"applianceVersion"`
	StartedAt        string          `json:"startedAt"`
	CompletedAt      string          `json:"completedAt,omitempty"`
	Status           string          `json:"status"`
	ExitCode         int             `json:"exitCode"`
	Message          string          `json:"message,omitempty"`
	Data             json.RawMessage `json:"data,omitempty"`
	Confirmation     *confirmation   `json:"confirmation,omitempty"`
}

// confirmation records how a destructive command's operator confirmation
// was supplied, per the command-result.v1 confirmation object.
type confirmation struct {
	Mode                 string `json:"mode"`
	AcknowledgedDataLoss bool   `json:"acknowledgedDataLoss"`
	Token                string `json:"token"`
}

func dispatch(spec commandSpec, opts cliOptions, logger *slog.Logger) commandResult {
	started := time.Now().UTC()
	result := commandResult{
		SchemaVersion:    1,
		Command:          spec.name,
		ApplianceVersion: version,
		StartedAt:        started.Format(time.RFC3339),
	}

	notImplemented := fmt.Sprintf("%s: not yet implemented (see docs/release-plan.md execution ledger)", spec.name)

	if !spec.mutating {
		switch spec.name {
		case "assemble-bundle":
			return runAssembleBundle(opts, logger, result)
		case "preflight":
			return runPreflight(opts, logger, result)
		case "status":
			return runStatus(opts, logger, result)
		case "verify":
			return runVerify(opts, logger, result)
		case "verify-bundle":
			return runVerifyBundle(opts, logger, result)
		case "support-bundle":
			return runSupportBundle(opts, logger, result)
		}
		logger.Info("running read-only command", "command", spec.name, "dryRun", opts.dryRun)
		return finish(result, "failed", 1, notImplemented, nil)
	}

	if !opts.dryRun {
		if err := os.MkdirAll(opts.stateDir, 0o750); err != nil {
			logger.Error("failed to prepare state directory", "error", err, "path", opts.stateDir)
			return finish(result, "failed", 1, err.Error(), nil)
		}
	}

	lockPath := filepath.Join(opts.stateDir, "installer.lock")
	journalPath := filepath.Join(opts.stateDir, "transaction.json")

	var lock *lifecycle.Lock
	if !opts.dryRun {
		acquired, err := lifecycle.AcquireLock(lockPath)
		if err != nil {
			logger.Error("failed to acquire installer lock", "error", err)
			return finish(result, "failed", 1, err.Error(), nil)
		}
		lock = acquired
		defer lock.Release()
	}

	journal := lifecycle.NewJournal(journalPath, opts.dryRun)

	current, err := journal.Current()
	if err != nil {
		logger.Error("failed to read transaction journal", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}
	if current != nil && current.Interrupted() && spec.name != "repair" {
		msg := fmt.Sprintf("a prior %s operation (transaction %s) did not complete; run 'zonctl repair' before starting a new operation", current.Type, current.ID)
		logger.Warn("interrupted prior operation detected", "transactionId", current.ID, "operation", current.Type)
		return finish(result, "failed", 1, msg, nil)
	}
	priorInstallAttempted := current != nil && current.Type == "install"

	txn, err := journal.Begin(spec.name, "", "")
	if err != nil {
		logger.Error("failed to begin transaction", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}
	logger.Info("began transaction", "transactionId", txn.ID, "command", spec.name, "dryRun", opts.dryRun)

	switch spec.name {
	case "install":
		result = runInstall(context.Background(), opts, txn, priorInstallAttempted, logger, result)
	case "repair":
		result = runRepair(context.Background(), opts, logger, result)
	case "backup":
		result = runBackup(context.Background(), opts, logger, result)
	case "restore":
		result = runRestore(context.Background(), opts, logger, result)
	case "upgrade":
		result = runUpgrade(context.Background(), opts, txn, logger, result)
	case "uninstall":
		result = runUninstall(context.Background(), opts, logger, result)
	case "factory-reset":
		result = runFactoryReset(context.Background(), opts, logger, result)
	default:
		// Command bodies land with the adapters that implement them
		// (R1-02/R1-03+); the skeleton always ends the transaction in a
		// terminal (non-interrupted) state so it never blocks a later run.
		result = finish(result, "failed", 1, notImplemented, nil)
	}

	if result.Status == "succeeded" {
		if err := journal.Complete(txn); err != nil {
			logger.Error("failed to record transaction outcome", "error", err)
		}
	} else if err := journal.Fail(txn); err != nil {
		logger.Error("failed to record transaction outcome", "error", err)
	}

	return result
}

func runPreflight(opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	facts, err := host.Detect(host.Options{DataDir: opts.stateDir, RequiredPorts: preflight.RequiredPorts})
	if err != nil {
		logger.Error("failed to detect host facts", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}

	checks := preflight.Run(facts)
	overall := preflight.OverallStatus(checks)

	reportID := "evidence-" + time.Now().UTC().Format("20060102T150405Z0700")
	report, err := preflight.BuildReport(checks, version, reportID, time.Now())
	if err != nil {
		logger.Error("failed to build preflight evidence report", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}
	if !opts.dryRun {
		if err := persistEvidence(opts.stateDir, reportID, report); err != nil {
			logger.Warn("failed to persist evidence report", "error", err)
		}
	}
	logger.Info("preflight complete", "overallStatus", overall, "evidenceReportId", reportID)

	data, _ := json.Marshal(map[string]string{"overallStatus": string(overall), "evidenceReportId": reportID})

	status := "succeeded"
	exitCode := 0
	message := fmt.Sprintf("preflight: %s", overall)
	if overall == preflight.StatusOperatorAction || overall == preflight.StatusUnsupported {
		status = "failed"
		exitCode = 1
	}
	return finish(result, status, exitCode, message, data)
}

// resolveInstallSource builds the verified bundle source install/upgrade
// read artifacts from in v1.
func resolveInstallSource(opts cliOptions) (install.Source, error) {
	if opts.bundleDir == "" {
		return nil, fmt.Errorf("--bundle-dir is required for v1 install/upgrade; connected installs are not supported")
	}
	pub, err := verify.LoadPublicKey("release-signing-key", opts.publicKey)
	if err != nil {
		return nil, fmt.Errorf("load release signing public key: %w", err)
	}
	return install.OfflineSource{BundleDir: opts.bundleDir, PublicKey: &pub}, nil
}

func runInstall(ctx context.Context, opts cliOptions, txn *lifecycle.Transaction, priorInstallAttempted bool, logger *slog.Logger, result commandResult) commandResult {
	source, err := resolveInstallSource(opts)
	if err != nil {
		logger.Error("failed to resolve install source", "error", err)
		return finish(result, "failed", 1, "install: "+err.Error(), nil)
	}

	installOpts := install.Options{
		ApplianceVersion:      version,
		InstalledStatePath:    filepath.Join(opts.stateDir, "installed-state.json"),
		K3sConfigPath:         defaultK3sConfigPath,
		K3sDataDir:            defaultK3sDataDir,
		K3sUnitPath:           defaultK3sUnitPath,
		K3sBinaryDestPath:     defaultK3sBinaryDestPath,
		K3sUnitName:           defaultK3sUnitName,
		KubeconfigPath:        defaultKubeconfigPath,
		NodeName:              opts.nodeName,
		ChartReleaseName:      "zon",
		ChartNamespace:        "zon",
		TransactionID:         txn.ID,
		PriorInstallAttempted: priorInstallAttempted,
		ForceAdopt:            opts.forceAdopt,
	}

	orch := install.NewOrchestrator()
	installed, checks, err := orch.Install(ctx, source, installOpts)

	reportID := "evidence-" + txn.ID
	if report, buildErr := evidence.BuildReport("install", version, reportID, checks, time.Now()); buildErr == nil {
		if !opts.dryRun {
			if persistErr := persistEvidence(opts.stateDir, reportID, report); persistErr != nil {
				logger.Warn("failed to persist evidence report", "error", persistErr)
			}
		}
	} else {
		logger.Warn("failed to build install evidence report", "error", buildErr)
	}

	if err != nil {
		logger.Error("install failed", "error", err, "transactionId", txn.ID)
		return finish(result, "failed", 1, err.Error(), nil)
	}

	logger.Info("install complete", "transactionId", txn.ID, "installedVersion", installed.InstalledVersion)
	data, _ := json.Marshal(map[string]string{
		"installedVersion": installed.InstalledVersion,
		"releaseId":        installed.InstalledReleaseID,
		"transactionId":    txn.ID,
	})
	return finish(result, "succeeded", 0, fmt.Sprintf("installed version %s", installed.InstalledVersion), data)
}

func persistEvidence(stateDir, reportID string, report []byte) error {
	dir := filepath.Join(stateDir, "evidence")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, reportID+".json"), report, 0o640)
}

func finish(result commandResult, status string, exitCode int, message string, data json.RawMessage) commandResult {
	result.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	result.Status = status
	result.ExitCode = exitCode
	result.Message = message
	result.Data = data
	return result
}

func emit(result commandResult, output string) int {
	data, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintln(os.Stderr, "zonctl: internal error marshaling result:", err)
		return 1
	}
	if err := manifest.Validate(manifest.KindCommandResult, data); err != nil {
		fmt.Fprintln(os.Stderr, "zonctl: internal error: result failed schema validation:", err)
		return 1
	}

	if output == "json" {
		fmt.Println(string(data))
	} else {
		fmt.Printf("%s: %s\n", result.Command, result.Message)
	}
	return result.ExitCode
}
