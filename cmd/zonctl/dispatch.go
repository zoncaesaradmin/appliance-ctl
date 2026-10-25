package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/cluster"
	"github.com/zoncaesaradmin/appliance-ctl/internal/clustertopology"
	"github.com/zoncaesaradmin/appliance-ctl/internal/configarchive"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/host"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdirs"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdns"
	"github.com/zoncaesaradmin/appliance-ctl/internal/install"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/lifecycle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/manifest"
	"github.com/zoncaesaradmin/appliance-ctl/internal/preflight"
	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
	"github.com/zoncaesaradmin/appliance-ctl/internal/recoveryset"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
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
			return runStatus(context.Background(), opts, logger, result)
		case "verify":
			return runVerify(context.Background(), opts, logger, result)
		case "verify-bundle":
			return runVerifyBundle(opts, logger, result)
		case "cluster-ha-check":
			return runClusterHACheck(context.Background(), opts, result)
		case "support-bundle":
			return runSupportBundle(context.Background(), opts, logger, result)
		case "configuration-export":
			return runConfigurationExport(context.Background(), opts, logger, result)
		case "configuration-list":
			return runConfigurationList(context.Background(), opts, result)
		}
		logger.Info("running read-only command", "command", spec.name, "dryRun", opts.dryRun)
		return finish(result, "failed", 1, notImplemented, nil)
	}
	// Verify the release and, for the new topology, the host inventory before
	// even creating a lifecycle journal or state directory. A bad bundle or
	// wrong-node inventory must not leave an install attempt on the target.
	if (spec.name == "install" || spec.name == "cluster-server-stage" || spec.name == "cluster-finalize") && opts.bundleDir != "" {
		if err := precheckInstallInputs(opts); err != nil {
			return finish(result, "failed", 1, spec.name+": "+err.Error(), nil)
		}
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
	// repair / uninstall / factory-reset are the recovery paths for a
	// crashed mid-operation host. Blocking uninstall here strands
	// --uninstall-first reinstall flows after --preserve-failed-state.
	if current != nil && current.Interrupted() && !((spec.name == "cluster-server-stage" && current.Type == "cluster-server-stage") || (spec.name == "cluster-finalize" && current.Type == "cluster-finalize")) && !allowsInterruptedRecovery(spec.name) {
		msg := fmt.Sprintf("a prior %s operation (transaction %s) did not complete; run 'zonctl repair' or 'zonctl uninstall --confirm yes' before starting a new operation", current.Type, current.ID)
		logger.Warn("interrupted prior operation detected", "transactionId", current.ID, "operation", current.Type)
		return finish(result, "failed", 1, msg, nil)
	}
	priorInstallAttempted := current != nil && current.Type == "install" && current.Interrupted()

	txn, err := journal.Begin(spec.name, "", "")
	if err != nil {
		logger.Error("failed to begin transaction", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}
	logger.Info("began transaction", "transactionId", txn.ID, "command", spec.name, "dryRun", opts.dryRun)

	switch spec.name {
	case "install":
		result = runInstall(context.Background(), opts, txn, priorInstallAttempted, logger, result)
	case "cluster-server-stage":
		result = runClusterServerStage(context.Background(), opts, logger, result)
	case "cluster-server-enrollment-create":
		result = runClusterServerEnrollmentCreate(opts, result)
	case "cluster-finalize":
		result = runClusterFinalize(context.Background(), opts, txn.ID, logger, result)
	case "repair":
		result = runRepair(context.Background(), opts, logger, result)
	case "backup":
		result = runBackup(context.Background(), opts, logger, result)
	case "restore":
		result = runRestore(context.Background(), opts, logger, result)
	case "upgrade":
		if err := requireControlPlaneLifecycle(opts); err != nil {
			result = finish(result, "failed", 1, err.Error(), nil)
			break
		}
		result = runUpgrade(context.Background(), opts, txn, logger, result)
	case "uninstall":
		result = runUninstall(context.Background(), opts, logger, result)
	case "factory-reset":
		if err := requireControlPlaneLifecycle(opts); err != nil {
			result = finish(result, "failed", 1, err.Error(), nil)
			break
		}
		result = runFactoryReset(context.Background(), opts, logger, result)
	case "models-import":
		result = runModelsImport(context.Background(), opts, logger, result)
	case "cluster-enrollment-create":
		result = runClusterEnrollmentCreate(opts, logger, result)
	case "cluster-join":
		result = runClusterJoin(context.Background(), opts, logger, result)
	case "cluster-worker-upgrade":
		result = runClusterWorkerUpgrade(context.Background(), opts, logger, result)
	case "cluster-node-register":
		result = runClusterNodeRegister(context.Background(), opts, logger, result)
	case "cluster-inference-deploy":
		result = runClusterInferenceDeploy(context.Background(), opts, logger, result)
	case "cluster-node-remove":
		result = runClusterNodeRemove(context.Background(), opts, logger, result)
	case "configuration-import":
		result = runConfigurationImport(context.Background(), opts, logger, result)
	case "configuration-list":
		result = runConfigurationList(context.Background(), opts, result)
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

func runClusterHACheck(ctx context.Context, opts cliOptions, result commandResult) commandResult {
	if opts.bundleDir == "" {
		return finish(result, "failed", 2, "cluster-ha-check: --bundle-dir is required", nil)
	}
	if opts.clusterInventoryPath == "" {
		return finish(result, "failed", 2, "cluster-ha-check: --cluster-inventory is required", nil)
	}
	profile := productconfig.SelectApplianceProfile(opts.applianceProfile, "")
	_, resolved, _, err := resolveVerifiedInstallSource(ctx, opts, profile)
	if err != nil {
		return finish(result, "failed", 1, "cluster-ha-check: "+err.Error(), nil)
	}
	if resolved.Compatibility.DeploymentTopology != clustertopology.ThreeServerEtcdV1 {
		return finish(result, "failed", 1, "cluster-ha-check: verified bundle does not declare embedded etcd", nil)
	}
	inventory, err := clustertopology.Load(opts.clusterInventoryPath)
	if err != nil {
		return finish(result, "failed", 1, "cluster-ha-check: "+err.Error(), nil)
	}
	addresses, err := clustertopology.LocalAddresses()
	if err != nil {
		return finish(result, "failed", 1, "cluster-ha-check: "+err.Error(), nil)
	}
	if err := inventory.ValidateLocalAddress(opts.nodeName, addresses); err != nil {
		return finish(result, "failed", 1, "cluster-ha-check: "+err.Error(), nil)
	}
	recordedUIDs := map[string]string{}
	if installed, err := state.Load(filepath.Join(opts.stateDir, "installed-state.json")); err != nil {
		return finish(result, "failed", 1, "cluster-ha-check: "+err.Error(), nil)
	} else if installed != nil && installed.Cluster != nil {
		if installed.InstalledReleaseID != resolved.ReleaseID {
			return finish(result, "failed", 1, "cluster-ha-check: installed receipt release differs from verified bundle", nil)
		}
		for _, node := range installed.Cluster.Nodes {
			recordedUIDs[node.Name] = node.NodeUID
		}
	}
	nodes := cluster.ValidateThreeServerNodeReadiness(ctx, cli.Exec, defaultKubeconfigPath, inventory, resolved.Compatibility.K3sVersion, recordedUIDs)
	apiEndpoints := cluster.ValidateThreeServerAPIEndpoints(ctx, cli.Exec, defaultKubeconfigPath, inventory)
	etcd := cluster.ReadLocalEtcdMembership(ctx, defaultK3sDataDir, inventory)
	data, _ := json.Marshal(map[string]bool{"kubernetesNodesReady": nodes.Healthy, "directAPIEndpointsReady": apiEndpoints.Healthy, "embeddedEtcdMembership": etcd.Healthy, "applicationHA": false})
	if !nodes.Healthy || !apiEndpoints.Healthy || !etcd.Healthy {
		return finish(result, "failed", 1, "cluster-ha-check: Kubernetes: "+nodes.Message+"; direct APIs: "+apiEndpoints.Message+"; etcd: "+etcd.Message, data)
	}
	return finish(result, "succeeded", 0, "cluster-ha-check: Kubernetes and embedded-etcd substrate pass; application HA is not established", data)
}

func precheckInstallInputs(opts cliOptions) error {
	profile := productconfig.SelectApplianceProfile(opts.applianceProfile, "")
	_, resolved, _, err := resolveVerifiedInstallSource(context.Background(), opts, profile)
	if err != nil {
		return err
	}
	if resolved.Compatibility.DeploymentTopology != clustertopology.ThreeServerEtcdV1 {
		return nil
	}
	inventory, err := clustertopology.Load(opts.clusterInventoryPath)
	if err != nil {
		return err
	}
	addresses, err := clustertopology.LocalAddresses()
	if err != nil {
		return err
	}
	return inventory.ValidateLocalAddress(opts.nodeName, addresses)
}

// localIPv4s is the LAN addresses of this host. Tests replace it.
var localIPv4s = hostdns.HostIPv4s

// requireControlPlaneLifecycle prevents node-local worker receipts from
// creating divergent backups, restores, upgrades, or factory resets. Worker
// maintenance must be orchestrated from the authoritative control-plane
// record; single-node and legacy receipts retain their existing behavior.
//
// Install records ControlPlaneNode as the dash-IP (192-168-1-155). Linux
// hostname is often zonsyssrv5; treat this host as the advertised prime when
// a local IPv4 matches that node name.
func requireControlPlaneLifecycle(opts cliOptions) error {
	installed, err := state.Load(filepath.Join(opts.stateDir, "installed-state.json"))
	if err != nil || installed == nil || installed.Cluster == nil {
		return err
	}
	control := strings.TrimSpace(installed.Cluster.ControlPlaneNode)
	if control == "" {
		return nil
	}
	if nodeIsThisHost(control, opts.nodeName, localIPv4s()) {
		return nil
	}
	return fmt.Errorf("cluster lifecycle operation must run on control-plane node %q; worker %q has a local receipt only", control, opts.nodeName)
}

func resolveApplianceNodeName(stateDir, hostname string) string {
	hostname = strings.TrimSpace(hostname)
	installed, err := state.Load(filepath.Join(stateDir, "installed-state.json"))
	if err == nil && installed != nil && installed.Cluster != nil {
		if name := localClusterNodeName(installed.Cluster, hostname); name != "" {
			return name
		}
	}
	return hostname
}

func localClusterNodeName(cluster *state.Cluster, hostname string) string {
	if cluster == nil {
		return ""
	}
	ips := localIPv4s()
	if nodeIsThisHost(cluster.ControlPlaneNode, hostname, ips) {
		return strings.TrimSpace(cluster.ControlPlaneNode)
	}
	for _, node := range cluster.Nodes {
		if nodeIsThisHost(node.Name, hostname, ips) {
			return strings.TrimSpace(node.Name)
		}
	}
	return ""
}

func nodeIsThisHost(nodeName, hostname string, localIPs []string) bool {
	nodeName = strings.TrimSpace(nodeName)
	if nodeName == "" {
		return false
	}
	if hostname != "" && nodeName == hostname {
		return true
	}
	ip, ok := state.IPv4FromNodeName(nodeName)
	if !ok {
		return false
	}
	for _, local := range localIPs {
		if local == ip {
			return true
		}
	}
	return false
}

func runPreflight(opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	signal, err := k3s.DetectService(defaultK3sUnitName)
	if err != nil {
		logger.Error("failed to detect k3s service", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}

	// Seed a durable /etc/hosts mapping before Detect so internal-dns-resolvable
	// (and sudo's hostname check) do not depend on flaky MagicDNS/uplink alone.
	// Ubuntu images often ship 127.0.1.1 under a different name than hostname(1).
	if hostname, hostErr := os.Hostname(); hostErr == nil {
		cfg := hostdns.PrepareConfig{
			Hostname: strings.TrimSpace(hostname),
			IPv4:     hostdns.PreferredLocalIPv4(),
		}
		if cfg.Hostname != "" && cfg.IPv4 != "" {
			if wrote, ensureErr := hostdns.EnsureNodeHostsEntry(cfg); ensureErr != nil {
				logger.Warn("failed to seed /etc/hosts for node hostname", "error", ensureErr, "hostname", cfg.Hostname)
			} else if wrote {
				logger.Info("seeded /etc/hosts so node hostname resolves for preflight", "hostname", cfg.Hostname, "ipv4", cfg.IPv4)
			}
		}
	}

	facts, err := host.Detect(host.Options{DataDir: opts.stateDir, RequiredPorts: preflight.RequiredPorts})
	if err != nil {
		logger.Error("failed to detect host facts", "error", err)
		return finish(result, "failed", 1, err.Error(), nil)
	}
	if signal.Detected && signal.Active {
		facts.PortsInUse = map[int]string{}
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
	return install.OfflineSource{BundleDir: opts.bundleDir, PackDirs: append([]string(nil), opts.packDirs...), PublicKey: &pub}, nil
}

type resolvedInstallSource struct {
	resolved install.Resolved
	checks   []evidence.Check
}

func (s resolvedInstallSource) Resolve(context.Context, string) (install.Resolved, []evidence.Check, error) {
	return s.resolved, s.checks, nil
}

func resolveVerifiedInstallSource(ctx context.Context, opts cliOptions, effectiveProfile string) (install.Source, install.Resolved, []evidence.Check, error) {
	source, err := resolveInstallSource(opts)
	if err != nil {
		return nil, install.Resolved{}, nil, err
	}
	resolved, checks, err := source.Resolve(ctx, effectiveProfile)
	if err != nil {
		return nil, resolved, checks, err
	}
	return resolvedInstallSource{resolved: resolved, checks: checks}, resolved, checks, nil
}

func runInstall(ctx context.Context, opts cliOptions, txn *lifecycle.Transaction, priorInstallAttempted bool, logger *slog.Logger, result commandResult) commandResult {
	effectiveProfile := productconfig.SelectApplianceProfile(opts.applianceProfile, "")
	source, resolved, resolveChecks, err := resolveVerifiedInstallSource(ctx, opts, effectiveProfile)
	installVersion := version
	if trimmed := strings.TrimSpace(resolved.BundleVersion); trimmed != "" {
		installVersion = trimmed
	}
	result.ApplianceVersion = installVersion
	if err != nil {
		logger.Error("failed to resolve install source", "error", err)
		reportID := "evidence-" + txn.ID
		reportPath := ""
		if len(resolveChecks) > 0 {
			if report, buildErr := evidence.BuildReport("install", installVersion, reportID, resolveChecks, time.Now()); buildErr == nil {
				if !opts.dryRun {
					if persistErr := persistEvidence(opts.stateDir, reportID, report); persistErr != nil {
						logger.Warn("failed to persist evidence report", "error", persistErr)
					} else {
						reportPath = evidenceReportPath(opts.stateDir, reportID)
					}
				}
			}
		}
		return finish(result, "failed", 1, withFailureDiagnostics("install: "+err.Error(), resolveChecks, reportPath), nil)
	}
	bootstrapPayload := []byte(nil)
	bootstrapArchiveID := ""
	bootstrapDatabaseRestorePath := ""
	bootstrapBlobRestorePath := ""
	bootstrapRecoverySetID := ""
	if opts.bootstrapMode == string(install.BootstrapRestoreConfig) {
		if opts.confirm != "restore-config" {
			return finish(result, "failed", 2, "install: --bootstrap-mode restore-config requires --confirm restore-config", nil)
		}
		if opts.configurationArchivePath == "" || opts.configurationArchiveKeyFile == "" {
			return finish(result, "failed", 2, "install: restore-config requires --configuration-archive and --configuration-archive-key-file", nil)
		}
		archive, readErr := os.ReadFile(opts.configurationArchivePath)
		if readErr != nil {
			return finish(result, "failed", 2, "install: read configuration archive: "+readErr.Error(), nil)
		}
		key, keyErr := readConfigurationArchiveKey(opts.configurationArchiveKeyFile)
		if keyErr != nil {
			return finish(result, "failed", 2, "install: "+keyErr.Error(), nil)
		}
		manifest, payload, openErr := configarchive.Open(archive, key)
		if openErr != nil {
			return finish(result, "failed", 2, "install: configuration archive verification failed: "+openErr.Error(), nil)
		}
		bootstrapPayload, bootstrapArchiveID = payload, manifest.ArchiveID
	}
	if opts.bootstrapMode == string(install.BootstrapRestoreRecoverySet) {
		if opts.confirm != "restore-recovery-set" {
			return finish(result, "failed", 2, "install: --bootstrap-mode restore-recovery-set requires --confirm restore-recovery-set", nil)
		}
		if opts.recoverySetPath == "" || opts.configurationArchiveKeyFile == "" {
			return finish(result, "failed", 2, "install: restore-recovery-set requires --recovery-set and --configuration-archive-key-file", nil)
		}
		set, loadErr := recoveryset.Load(opts.recoverySetPath)
		if loadErr != nil {
			return finish(result, "failed", 2, "install: recovery-set verification failed: "+loadErr.Error(), nil)
		}
		if verifyErr := recoveryset.VerifyFiles(opts.recoverySetPath, set); verifyErr != nil {
			return finish(result, "failed", 2, "install: recovery-set verification failed: "+verifyErr.Error(), nil)
		}
		if set.PlatformVersion != "" && strings.TrimSpace(resolved.BundleVersion) != "" && set.PlatformVersion != resolved.BundleVersion {
			return finish(result, "failed", 2, "install: recovery-set platform version does not match the signed bundle", nil)
		}
		recoveredState, stateErr := state.Load(filepath.Join(opts.recoverySetPath, "installed-state.json"))
		if stateErr != nil || recoveredState == nil || recoveredState.Components.DatabaseEngine != "postgres" || recoveredState.Components.PostgresImageReference != resolved.PostgresImageReference {
			return finish(result, "failed", 2, "install: recovery-set database image is incompatible with the signed bundle", nil)
		}
		key, keyErr := readConfigurationArchiveKey(opts.configurationArchiveKeyFile)
		if keyErr != nil {
			return finish(result, "failed", 2, "install: "+keyErr.Error(), nil)
		}
		archive, readErr := os.ReadFile(filepath.Join(opts.recoverySetPath, set.ConfigurationArchive))
		if readErr != nil {
			return finish(result, "failed", 2, "install: read recovery-set configuration archive: "+readErr.Error(), nil)
		}
		if _, _, openErr := configarchive.Open(archive, key); openErr != nil {
			return finish(result, "failed", 2, "install: recovery-set configuration archive verification failed: "+openErr.Error(), nil)
		}
		bootstrapDatabaseRestorePath = filepath.Join(opts.recoverySetPath, set.Database.Path)
		foundBlob := false
		for _, artifact := range set.Artifacts {
			if artifact.Path == "blob-storage.tar" {
				bootstrapBlobRestorePath, foundBlob = filepath.Join(opts.recoverySetPath, artifact.Path), true
				break
			}
		}
		if !foundBlob {
			return finish(result, "failed", 2, "install: system backup does not include required blob-storage artifact", nil)
		}
		bootstrapRecoverySetID = set.ID
	}
	installOpts := install.Options{
		ApplianceVersion:                version,
		ClusterInventoryPath:            opts.clusterInventoryPath,
		InstalledStatePath:              filepath.Join(opts.stateDir, "installed-state.json"),
		K3sConfigPath:                   defaultK3sConfigPath,
		K3sRegistriesPath:               defaultK3sRegistriesPath,
		K3sDataDir:                      defaultK3sDataDir,
		K3sUnitPath:                     defaultK3sUnitPath,
		K3sBinaryDestPath:               defaultK3sBinaryDestPath,
		KubectlSymlinkPath:              defaultKubectlSymlinkPath,
		K3sCNINetworkDir:                defaultK3sCNINetworkDir,
		K3sCNIInterfaces:                append([]string(nil), defaultK3sCNIInterfaces...),
		K3sUnitName:                     defaultK3sUnitName,
		KubeconfigPath:                  defaultKubeconfigPath,
		HostAgentBinaryDestPath:         defaultHostAgentBinaryPath,
		HostAgentUnitPath:               defaultHostAgentUnitPath,
		HostAgentUnitName:               defaultHostAgentUnitName,
		HostAgentSocketPath:             defaultHostAgentSocketPath,
		HostAgentLogPath:                defaultHostAgentLogPath,
		ApplianceProfile:                opts.applianceProfile,
		WorkspaceRootDir:                defaultWorkspaceRootDir,
		MetadataBundlesDir:              hostdirs.MetadataBundlesDir,
		NodeName:                        opts.nodeName,
		ApplianceName:                   opts.applianceName,
		DNSZone:                         opts.dnsZone,
		TLSSANs:                         installTLSSANs(opts),
		ZonctlRealDestPath:              defaultZonctlRealPath,
		ZonctlLauncherDestPath:          defaultZonctlLauncherPath,
		ChartReleaseName:                defaultChartReleaseName,
		ChartNamespace:                  defaultChartNamespace,
		TransactionID:                   txn.ID,
		PriorInstallAttempted:           priorInstallAttempted,
		ForceAdopt:                      opts.forceAdopt,
		PreserveFailedState:             opts.preserveFailedState,
		ClusterInit:                     opts.clusterInit,
		BootstrapMode:                   install.BootstrapMode(opts.bootstrapMode),
		BootstrapConfigurationPayload:   bootstrapPayload,
		BootstrapConfigurationArchiveID: bootstrapArchiveID,
		BootstrapDatabaseRestorePath:    bootstrapDatabaseRestorePath,
		BootstrapBlobRestorePath:        bootstrapBlobRestorePath,
		BootstrapRecoverySetID:          bootstrapRecoverySetID,
		ControlPlaneDatabaseDataDir:     hostdirs.ControlPlaneDatabaseDataDir,
	}
	imagePullRegistry, err := resolveImagePullRegistry(opts, nil)
	if err != nil {
		logger.Error("invalid image pull registry options", "error", err)
		return finish(result, "failed", 1, "install: "+err.Error(), nil)
	}
	installOpts.ImagePullRegistry = imagePullRegistry

	orch := install.NewOrchestrator()
	installed, checks, err := orch.Install(ctx, source, installOpts)

	reportID := "evidence-" + txn.ID
	reportPath := ""
	if report, buildErr := evidence.BuildReport("install", installVersion, reportID, checks, time.Now()); buildErr == nil {
		if !opts.dryRun {
			if persistErr := persistEvidence(opts.stateDir, reportID, report); persistErr != nil {
				logger.Warn("failed to persist evidence report", "error", persistErr)
			} else {
				reportPath = evidenceReportPath(opts.stateDir, reportID)
			}
		}
	} else {
		logger.Warn("failed to build install evidence report", "error", buildErr)
	}

	if err != nil {
		logger.Error("install failed", "error", err, "transactionId", txn.ID)
		return finish(result, "failed", 1, withFailureDiagnostics(err.Error(), checks, reportPath), nil)
	}

	logger.Info("install complete", "transactionId", txn.ID, "installedVersion", installed.InstalledVersion)
	data, _ := json.Marshal(map[string]string{
		"installedVersion": installed.InstalledVersion,
		"releaseId":        installed.InstalledReleaseID,
		"transactionId":    txn.ID,
		"applianceProfile": installed.ApplianceProfile,
		"metadataVersion":  installed.Components.MetadataVersion,
		"metadataDigest":   installed.Components.MetadataDigest,
	})
	return finish(result, "succeeded", 0, fmt.Sprintf("installed version %s with appliance profile %s; Metadata bundle: %s; Licensing: not configured; complete licensing setup after first login", installed.InstalledVersion, installed.ApplianceProfile, installed.Components.MetadataVersion), data)
}

func persistEvidence(stateDir, reportID string, report []byte) error {
	dir := filepath.Join(stateDir, "evidence")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, reportID+".json"), report, 0o640)
}

func evidenceReportPath(stateDir, reportID string) string {
	return filepath.Join(stateDir, "evidence", reportID+".json")
}

func withFailureDiagnostics(message string, checks []evidence.Check, reportPath string) string {
	message = strings.TrimSpace(message)
	if reportPath != "" {
		message += "; evidence report: " + reportPath
	}
	if summary := firstOperatorActionSummary(checks); summary != "" {
		message += "; first diagnostic: " + summary
	}
	return message
}

func firstOperatorActionSummary(checks []evidence.Check) string {
	for _, check := range checks {
		if check.Status != evidence.StatusOperatorAction {
			continue
		}
		msg := strings.Join(strings.Fields(check.Message), " ")
		if msg == "" {
			msg = check.ID
		} else {
			msg = check.ID + ": " + msg
		}
		const limit = 320
		if len(msg) > limit {
			return msg[:limit] + "..."
		}
		return msg
	}
	return ""
}

func finish(result commandResult, status string, exitCode int, message string, data json.RawMessage) commandResult {
	result.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	result.Status = status
	result.ExitCode = exitCode
	result.Message = message
	result.Data = data
	return result
}

func allowsInterruptedRecovery(command string) bool {
	switch command {
	case "repair", "uninstall", "factory-reset":
		return true
	default:
		return false
	}
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
