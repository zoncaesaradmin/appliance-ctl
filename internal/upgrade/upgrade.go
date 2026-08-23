package upgrade

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/backup"
	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/helm"
	"github.com/zoncaesaradmin/appliance-ctl/internal/host"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostagent"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdirs"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdns"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostpackages"
	"github.com/zoncaesaradmin/appliance-ctl/internal/images"
	"github.com/zoncaesaradmin/appliance-ctl/internal/install"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
	"github.com/zoncaesaradmin/appliance-ctl/internal/zonctlhost"
)

// Options fully parameterizes an upgrade. Every path is explicit, as in
// internal/install, so tests can redirect every mutating operation.
// Target release artifact resolution is the caller's install.Source, not
// part of Options.
type Options struct {
	TargetApplianceVersion string

	InstalledStatePath      string
	K3sConfigPath           string
	K3sUnitPath             string
	K3sBinaryDestPath       string
	K3sUnitName             string
	K3sDataDir              string
	KubeconfigPath          string
	HostAgentBinaryDestPath string
	HostAgentUnitPath       string
	HostAgentUnitName       string
	HostAgentSocketPath     string
	HostAgentLogPath        string
	ApplianceProfile        string
	// WorkspaceRootDir is the host directory backing the workspace
	// storage hostPath PersistentVolume (builder profile only). See
	// internal/hostdirs — re-applied on every upgrade so a host whose
	// directory was created before this fix shipped self-heals.
	WorkspaceRootDir string
	// MetadataBundlesDir is the host directory for extracted metadata bundles.
	// Empty defaults to hostdirs.MetadataBundlesDir.
	MetadataBundlesDir string
	NodeName           string
	ApplianceName      string
	DNSZone            string
	// Host packages from the super-set bundle are staged when present so day-2
	// host APIs can enable mDNS / client Wi-Fi / Wi-Fi AP. Services are not enabled here.
	TLSSANs                []string
	ZonctlRealDestPath     string
	ZonctlLauncherDestPath string

	ChartReleaseName string
	ChartNamespace   string

	// K3sRegistriesPath / ImagePullRegistry mirror install.Options: optional
	// private registry for containerd pulls (see k3s.RegistriesConfig).
	K3sRegistriesPath string
	ImagePullRegistry k3s.RegistriesConfig

	BackupRoot    string
	TransactionID string

	// PreserveFailedState disables rollback-to-backup on failure so the
	// partially upgraded host can be inspected in place for debugging.
	// The default remains rollback for normal operator use.
	PreserveFailedState bool
}

const (
	registryReleaseName      = "appliance-registry"
	messageBrokerReleaseName = "appliance-message-broker"
	messageBrokerNamespace   = "ace-system"
	registryNamespace        = "artifacts"
	workflowsReleaseName     = "appliance-workflows"
	workflowsNamespace       = "workflows"
	dnsReleaseName           = "appliance-dns"
	dnsNamespace             = "dns"
	inferenceReleaseName     = "appliance-inference"
	inferenceNamespace       = "inference"
	videoReleaseName         = "appliance-video"
	videoNamespace           = "video"
)

// Orchestrator holds the injectable adapters Upgrade drives.
type Orchestrator struct {
	K3s       k3s.Ops
	ImagesRun cli.Runner
	HelmRun   cli.Runner
	// EnsureOwnedDir prepares a host directory backing a static hostPath
	// PersistentVolume with the correct owner; see internal/hostdirs.
	EnsureOwnedDir func(path string, uid, gid int, perm os.FileMode) error
	// EnsureOwnedFile reseeds operator-facing log files to a host-readable mode.
	EnsureOwnedFile     func(path string, uid, gid int, perm os.FileMode) error
	PrepareHostDNS      func(hostdns.PrepareConfig) (hostdns.PrepareResult, error)
	RestoreHostDNS      func() error
	DetectHost          func(host.Options) (host.Facts, error)
	InstallHostAgent    func(hostagent.InstallSpec) (func() error, error)
	InstallHostPackages func(hostpackages.InstallSpec) (func() error, error)
}

// NewOrchestrator wires an Orchestrator to the real adapters.
func NewOrchestrator() *Orchestrator {
	return &Orchestrator{
		K3s: k3s.DefaultOps(), ImagesRun: cli.Exec, HelmRun: cli.Exec,
		EnsureOwnedDir: func(path string, uid, gid int, perm os.FileMode) error {
			return hostdirs.EnsureOwnedDir(path, uid, gid, perm, os.Chown)
		},
		EnsureOwnedFile: func(path string, uid, gid int, perm os.FileMode) error {
			return hostdirs.EnsureOwnedFile(path, uid, gid, perm, os.Chown)
		},
		PrepareHostDNS:      hostdns.Prepare,
		RestoreHostDNS:      hostdns.Restore,
		DetectHost:          host.Detect,
		InstallHostAgent:    hostagent.InstallOrUpdate,
		InstallHostPackages: hostpackages.InstallRequiredPackages,
	}
}

// Upgrade runs the N-1 upgrade sequence: verify the target bundle is a
// supported upgrade from what's installed, take and verify a mandatory
// pre-upgrade backup, stage new images, swap the K3s binary only if its
// version actually changed (preserving the prior binary/config/unit for
// rollback), apply the new chart, then persist the new
// installed-state. Any failure after the backup is taken triggers a
// restore-based rollback: the K3s binary/config/unit (if changed) are put
// back and the data directory is restored from the pre-upgrade backup.
//
// Coordinating in-flight workflows and running product migration hooks
// (Upgrade Sequence steps 3 and 7's "supported hooks") depend on
// appliance-code capabilities not yet integrated here; this is a known
// gap, not a silent omission.
func (o *Orchestrator) Upgrade(ctx context.Context, source install.Source, opts Options) (*state.InstalledState, []evidence.Check, error) {
	var checks []evidence.Check

	installed, err := state.Load(opts.InstalledStatePath)
	if err != nil {
		return nil, checks, fmt.Errorf("upgrade: %w", err)
	}
	if installed == nil {
		return nil, checks, fmt.Errorf("upgrade: nothing is installed; run install first")
	}
	if !installed.K3sOwnership.Owned {
		return nil, checks, fmt.Errorf("upgrade: installed-state does not record appliance ownership")
	}

	requestedProfile := strings.TrimSpace(opts.ApplianceProfile)
	if requestedProfile == "" {
		requestedProfile = strings.TrimSpace(installed.ApplianceProfile)
	}
	resolved, resolveChecks, err := source.Resolve(ctx, requestedProfile)
	checks = append(checks, resolveChecks...)
	if err != nil {
		return nil, checks, fmt.Errorf("upgrade: %w", err)
	}
	effectiveProfile := resolved.EffectiveProfile
	targetVersion := strings.TrimSpace(resolved.BundleVersion)
	if targetVersion == "" {
		targetVersion = strings.TrimSpace(opts.TargetApplianceVersion)
	}
	if targetVersion == "" {
		return nil, checks, fmt.Errorf("upgrade: resolved bundle version is empty")
	}
	sameVersionRefresh := strings.TrimSpace(installed.InstalledVersion) == targetVersion
	hadArtifactBefore := productconfig.HasCapability(installed.ApplianceProfile, productconfig.CapabilityArtifact)
	hadFilesBefore := productconfig.HasCapability(installed.ApplianceProfile, productconfig.CapabilityFiles)
	hadWorkflowsBefore := productconfig.HasCapability(installed.ApplianceProfile, productconfig.CapabilityWorkflows)
	hadDNSBefore := productconfig.HasCapability(installed.ApplianceProfile, productconfig.CapabilityDNS)
	hadInferenceBefore := productconfig.HasCapability(installed.ApplianceProfile, productconfig.CapabilityInference)
	hadVideoBefore := productconfig.HasCapability(installed.ApplianceProfile, productconfig.CapabilityVideo)
	targetArtifact := resolved.ArtifactEnabled
	targetFiles := resolved.FilesEnabled
	targetWorkflows := resolved.WorkflowsEnabled
	targetDNS := resolved.DNSEnabled
	targetInference := resolved.InferenceEnabled
	targetVideo := resolved.VideoEnabled
	targetBuild := resolved.BuildEnabled
	targetHost := resolved.HostEnabled
	if hadArtifactBefore && !targetArtifact {
		return nil, checks, fmt.Errorf("upgrade: changing from artifact-capable profile %q to non-artifact profile %q is not supported in place; reinstall with the target profile instead", installed.ApplianceProfile, effectiveProfile)
	}
	if hadFilesBefore && !targetFiles {
		return nil, checks, fmt.Errorf("upgrade: changing from files-capable profile %q to non-files profile %q is not supported in place; reinstall with the target profile instead", installed.ApplianceProfile, effectiveProfile)
	}
	if hadDNSBefore && !targetDNS {
		return nil, checks, fmt.Errorf("upgrade: changing from dns-capable profile %q to non-dns profile %q is not supported in place; reinstall with the target profile instead", installed.ApplianceProfile, effectiveProfile)
	}
	if hadInferenceBefore && !targetInference {
		return nil, checks, fmt.Errorf("upgrade: changing from inference-capable profile %q to non-inference profile %q is not supported in place; reinstall with the target profile instead", installed.ApplianceProfile, effectiveProfile)
	}
	if hadVideoBefore && !targetVideo {
		return nil, checks, fmt.Errorf("upgrade: changing from video-capable profile %q to non-video profile %q is not supported in place; reinstall with the target profile instead", installed.ApplianceProfile, effectiveProfile)
	}
	applianceName := strings.TrimSpace(opts.ApplianceName)
	if applianceName == "" {
		applianceName = strings.TrimSpace(installed.ApplianceName)
	}
	dnsZone := strings.TrimSpace(opts.DNSZone)
	if dnsZone == "" {
		dnsZone = strings.TrimSpace(installed.DNSZone)
	}
	identity, err := productconfig.ResolveApplianceIdentity(applianceName, dnsZone)
	if err != nil {
		return nil, checks, fmt.Errorf("upgrade: %w", err)
	}
	detectHost := o.DetectHost
	if detectHost == nil {
		detectHost = host.Detect
	}
	facts, err := detectHost(host.Options{DataDir: opts.K3sDataDir})
	if err != nil {
		return nil, checks, fmt.Errorf("upgrade: detect host: %w", err)
	}
	baselineCheck := install.CheckBundleHostBaseline(facts, resolved.HostBaseline)
	checks = append(checks, baselineCheck)
	if baselineCheck.Status != evidence.StatusPass {
		return nil, checks, fmt.Errorf("upgrade: target host does not match the signed bundle baseline")
	}
	// Always include the derived FQDN even when the CLI computed TLSSANs before
	// installed-state identity was known (omitted --appliance-name/--dns-zone).
	tlsSANs := withApplianceFQDN(identity.FQDN, opts.TLSSANs...)
	nodeIPv4 := preferredUpgradeLocalIPv4(tlsSANs...)
	preparedValuesPath, cleanupPreparedValues, err := productconfig.PrepareValuesFile(resolved.ConfigurationPath, effectiveProfile, resolved.CatalogPath, resolved.WorkspaceProvisionerImageReference, resolved.BuilderImageReference, resolved.HostAgentImageReference, identity.Name, identity.Zone, nodeIPv4, resolved.ArtifactServerImageReference)
	if err != nil {
		return nil, checks, fmt.Errorf("upgrade: %w", err)
	}
	defer cleanupPreparedValues()
	registryValuesPath := ""
	cleanupRegistryValues := func() {}
	if targetArtifact {
		registryValuesPath, cleanupRegistryValues, err = productconfig.PrepareRegistryValuesFile(filepath.Dir(resolved.ConfigurationPath), resolved.ArtifactServerImageReference, identity.FQDN)
		if err != nil {
			return nil, checks, fmt.Errorf("upgrade: %w", err)
		}
		defer cleanupRegistryValues()
	}
	dnsValuesPath := ""
	cleanupDNSValues := func() {}
	if targetDNS {
		dnsValuesPath, cleanupDNSValues, err = productconfig.PrepareDNSValuesFile(filepath.Dir(resolved.ConfigurationPath), resolved.DNSImageReference, identity.Zone, nodeIPv4)
		if err != nil {
			return nil, checks, fmt.Errorf("upgrade: %w", err)
		}
		defer cleanupDNSValues()
	}
	inferenceValuesPath := ""
	cleanupInferenceValues := func() {}
	if targetInference {
		inferenceValuesPath, cleanupInferenceValues, err = productconfig.PrepareInferenceValuesFile(filepath.Dir(resolved.ConfigurationPath), resolved.InferenceImageReference)
		if err != nil {
			return nil, checks, fmt.Errorf("upgrade: %w", err)
		}
		defer cleanupInferenceValues()
	}
	videoValuesPath := ""
	cleanupVideoValues := func() {}
	if targetVideo {
		videoValuesPath, cleanupVideoValues, err = productconfig.PrepareVideoValuesFile(filepath.Dir(resolved.ConfigurationPath), resolved.VideoImageReference)
		if err != nil {
			return nil, checks, fmt.Errorf("upgrade: %w", err)
		}
		defer cleanupVideoValues()
	}

	// Gated on the Build capability, not the "builder" profile name
	// directly: more than one profile can enable Build, and this
	// directory only needs to exist when Build does. Re-applied on every
	// upgrade (not just once at install time) so a host whose workspace
	// directory was created before this fix shipped — or whose ownership
	// drifted for any other reason — self-heals here rather than needing
	// a manual chown. See internal/hostdirs for why this can't be left
	// to Kubernetes' own fsGroup handling.
	if targetBuild && opts.WorkspaceRootDir != "" {
		if err := o.EnsureOwnedDir(opts.WorkspaceRootDir, hostdirs.ApplianceDirOwnerUID, hostdirs.ApplianceSharedFSGID, hostdirs.WorkspaceDirMode); err != nil {
			return nil, checks, fmt.Errorf("upgrade: prepare workspace directory: %w", err)
		}
		checks = append(checks, evidence.Check{
			ID: "workspace-directory-owned", Category: "host", Status: evidence.StatusPass,
			Message:   fmt.Sprintf("%s owned by %d:%d", opts.WorkspaceRootDir, hostdirs.ApplianceDirOwnerUID, hostdirs.ApplianceSharedFSGID),
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
	}
	if targetInference {
		if err := o.EnsureOwnedDir(hostdirs.InferenceModelsDir, hostdirs.InferenceDirOwnerUID, hostdirs.ApplianceSharedFSGID, hostdirs.WorkspaceDirMode); err != nil {
			return nil, checks, fmt.Errorf("upgrade: prepare inference models directory: %w", err)
		}
		checks = append(checks, evidence.Check{
			ID: "inference-models-directory-owned", Category: "host", Status: evidence.StatusPass,
			Message:   fmt.Sprintf("%s owned by %d:%d", hostdirs.InferenceModelsDir, hostdirs.InferenceDirOwnerUID, hostdirs.ApplianceSharedFSGID),
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
	}
	if targetVideo {
		if err := o.EnsureOwnedDir(hostdirs.VideoLibraryDir, hostdirs.VideoDirOwnerUID, hostdirs.ApplianceSharedFSGID, hostdirs.WorkspaceDirMode); err != nil {
			return nil, checks, fmt.Errorf("upgrade: prepare video library directory: %w", err)
		}
		checks = append(checks, evidence.Check{
			ID: "video-library-directory-owned", Category: "host", Status: evidence.StatusPass,
			Message:   fmt.Sprintf("%s owned by %d:%d", hostdirs.VideoLibraryDir, hostdirs.VideoDirOwnerUID, hostdirs.ApplianceSharedFSGID),
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
	}

	metadataBundlesDir := strings.TrimSpace(opts.MetadataBundlesDir)
	if metadataBundlesDir == "" {
		metadataBundlesDir = hostdirs.MetadataBundlesDir
	}
	if err := o.EnsureOwnedDir(metadataBundlesDir, hostdirs.AutomationRuntimeDirOwnerUID, hostdirs.ApplianceSharedFSGID, hostdirs.SharedWritableDirMode); err != nil {
		return nil, checks, fmt.Errorf("upgrade: prepare metadata-bundles directory: %w", err)
	}
	checks = append(checks, evidence.Check{
		ID: "metadata-bundles-directory-owned", Category: "host", Status: evidence.StatusPass,
		Message:   fmt.Sprintf("%s owned by %d:%d", metadataBundlesDir, hostdirs.AutomationRuntimeDirOwnerUID, hostdirs.ApplianceSharedFSGID),
		Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	})
	metadataVersion, metadataDigest, err := install.StageMetadataBundle(
		resolved.MetadataBundleArchivePath,
		filepath.Join(filepath.Dir(opts.InstalledStatePath), "metadata-bundles"),
		metadataBundlesDir,
		effectiveProfile,
	)
	if err != nil {
		return nil, checks, fmt.Errorf("upgrade: stage metadata bundle: %w", err)
	}
	checks = append(checks, evidence.Check{
		ID: "metadata-bundle-staged", Category: "manifest", Status: evidence.StatusPass,
		Message:   fmt.Sprintf("staged and extracted metadata bundle %s (profile %s validated)", metadataVersion, effectiveProfile),
		Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	})

	if !sameVersionRefresh && !isSupportedSource(installed.InstalledVersion, resolved.Compatibility.SupportedUpgradeSources) {
		return nil, checks, fmt.Errorf("upgrade: %s is not a supported upgrade source for target %s (supported: %v)", installed.InstalledVersion, targetVersion, resolved.Compatibility.SupportedUpgradeSources)
	}
	k3sBinarySrc := resolved.K3sBinaryPath
	chartPath := resolved.ChartPath

	// Mandatory pre-upgrade recovery set.
	backupManifest, backupChecks, err := backup.Create(ctx, o.K3s, opts.K3sUnitName, opts.K3sDataDir, opts.BackupRoot, installed.InstalledVersion, metadataBundlesDir, installed.Components.MetadataVersion, installed.Components.MetadataDigest)
	checks = append(checks, backupChecks...)
	if err != nil {
		return nil, checks, fmt.Errorf("upgrade: pre-upgrade backup failed: %w", err)
	}
	backupDir := filepath.Join(opts.BackupRoot, backupManifest.BackupID)
	verifyChecks, err := backup.Verify(backupDir)
	checks = append(checks, verifyChecks...)
	if err != nil {
		return nil, checks, fmt.Errorf("upgrade: pre-upgrade backup failed integrity verification: %w", err)
	}
	failUpgrade := func(primary error, cleanup func() []evidence.Check) ([]evidence.Check, error) {
		if opts.PreserveFailedState {
			return nil, fmt.Errorf("%w (failed state preserved due to --preserve-failed-state)", primary)
		}
		return cleanup(), fmt.Errorf("%w (rolled back to pre-upgrade backup)", primary)
	}

	binaryReverted := false
	restoreHostDNSOnRollback := false
	var hostPackagesRollback func() error
	var hostAgentRollback func() error
	rollback := func() []evidence.Check {
		var rc []evidence.Check
		var rollbackErrs []error
		if binaryReverted {
			for _, path := range []string{opts.K3sBinaryDestPath, opts.K3sConfigPath, opts.K3sUnitPath} {
				if err := revertFile(path); err != nil {
					rollbackErrs = append(rollbackErrs, err)
				}
			}
		}
		if restoreHostDNSOnRollback && o.RestoreHostDNS != nil {
			if err := o.RestoreHostDNS(); err != nil {
				rollbackErrs = append(rollbackErrs, err)
			}
		}
		if hostPackagesRollback != nil {
			if err := hostPackagesRollback(); err != nil {
				rollbackErrs = append(rollbackErrs, err)
			}
		}
		if hostAgentRollback != nil {
			if err := hostAgentRollback(); err != nil {
				rollbackErrs = append(rollbackErrs, err)
			}
		}
		restoreChecks, restoreErr := backup.Restore(ctx, o.K3s, opts.K3sUnitName, backupDir, opts.K3sDataDir, metadataBundlesDir)
		rc = append(rc, restoreChecks...)
		if restoreErr != nil {
			rollbackErrs = append(rollbackErrs, restoreErr)
		}
		if len(rollbackErrs) > 0 {
			rc = append(rc, evidence.Check{
				ID: "upgrade-rollback", Category: "backup-restore", Status: evidence.StatusFail,
				Message: errors.Join(rollbackErrs...).Error(), Timestamp: time.Now().UTC(),
				Idempotent: true, SecretsRedacted: true,
			})
		}
		return rc
	}

	importer := &images.Importer{Run: o.ImagesRun, Namespace: "k8s.io"}
	imgs := append(append([]images.Image{}, resolved.K3sImages...), resolved.FilterOCIImages(resolved.OCIImages)...)
	preloadResult, err := importer.PreloadAll(ctx, imgs)
	checks = append(checks, preloadResult.Checks...)
	if err != nil {
		rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", err), func() []evidence.Check {
			_ = importer.Rollback(ctx, preloadResult.NewlyImported)
			return rollback()
		})
		checks = append(checks, rollbackChecks...)
		return nil, checks, failErr
	}

	k3sVersionChanged := resolved.Compatibility.K3sVersion != installed.Components.K3sVersion
	binaryCheck := evidence.Check{ID: "upgrade-k3s-binary", Category: "k3s", Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true}
	if k3sVersionChanged {
		snapPaths := []string{opts.K3sBinaryDestPath, opts.K3sConfigPath, opts.K3sUnitPath}
		if p := strings.TrimSpace(opts.K3sRegistriesPath); p != "" {
			if _, err := os.Stat(p); err == nil {
				snapPaths = append(snapPaths, p)
			}
		}
		for _, path := range snapPaths {
			if err := snapshotFile(path); err != nil {
				rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: preserve current k3s files: %w", err), func() []evidence.Check {
					_ = importer.Rollback(ctx, preloadResult.NewlyImported)
					return rollback()
				})
				checks = append(checks, rollbackChecks...)
				return nil, checks, failErr
			}
		}
		binaryReverted = true

		steps := []struct {
			name string
			run  func() error
		}{
			{"stop", func() error { return o.K3s.Stop(opts.K3sUnitName) }},
			{"write config", func() error {
				return o.K3s.WriteConfig(opts.K3sConfigPath, k3s.Config{NodeName: opts.NodeName, DataDir: opts.K3sDataDir, TLSSANs: tlsSANs})
			}},
			{"write registries", func() error { return writeImagePullRegistries(o.K3s, opts) }},
			{"write unit", func() error {
				return o.K3s.WriteUnit(opts.K3sUnitPath, k3s.UnitConfig{BinaryPath: opts.K3sBinaryDestPath, ConfigPath: opts.K3sConfigPath})
			}},
			{"install binary", func() error { return o.K3s.InstallBinary(k3sBinarySrc, opts.K3sBinaryDestPath) }},
			{"start", func() error { return o.K3s.EnableAndStart(opts.K3sUnitName) }},
		}
		for _, step := range steps {
			if err := step.run(); err != nil {
				rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %s k3s: %w", step.name, err), func() []evidence.Check {
					_ = importer.Rollback(ctx, preloadResult.NewlyImported)
					return rollback()
				})
				checks = append(checks, rollbackChecks...)
				return nil, checks, failErr
			}
		}
		binaryCheck.Status = evidence.StatusPass
		binaryCheck.Message = fmt.Sprintf("k3s upgraded from %s to %s", installed.Components.K3sVersion, resolved.Compatibility.K3sVersion)
	} else {
		binaryCheck.Status = evidence.StatusPass
		binaryCheck.Message = "k3s version unchanged; binary not replaced"
		if err := writeImagePullRegistries(o.K3s, opts); err != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", err), func() []evidence.Check {
				_ = importer.Rollback(ctx, preloadResult.NewlyImported)
				return rollback()
			})
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
		if strings.TrimSpace(opts.ImagePullRegistry.Registry) != "" {
			if err := o.K3s.Restart(opts.K3sUnitName); err != nil {
				rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: restart k3s after registries.yaml: %w", err), func() []evidence.Check {
					_ = importer.Rollback(ctx, preloadResult.NewlyImported)
					return rollback()
				})
				checks = append(checks, rollbackChecks...)
				return nil, checks, failErr
			}
			checks = append(checks, evidence.Check{
				ID: "k3s-registries-restart", Category: "k3s", Status: evidence.StatusPass,
				Message: "k3s restarted to load image-pull registries.yaml", Timestamp: time.Now().UTC(),
				Idempotent: true, SecretsRedacted: true,
			})
		}
	}
	checks = append(checks, binaryCheck)
	// Install offline host packages for every profile (day-2 mDNS / client Wi-Fi / Wi-Fi AP);
	// do not enable those features here. NewOrchestrator wires the real dpkg
	// installer; unit tests inject stubs.
	if resolved.HostPackagesRootDir == "" {
		rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: host-packages are required in the signed bundle (mdns + wifi-client + wifi-ap)"), rollback)
		checks = append(checks, rollbackChecks...)
		return nil, checks, failErr
	}
	installHostPackages := o.InstallHostPackages
	if installHostPackages == nil {
		installHostPackages = func(hostpackages.InstallSpec) (func() error, error) {
			return func() error { return nil }, nil
		}
	}
	hostPackagesRollback, err = installHostPackages(hostpackages.InstallSpec{
		RootDir:   resolved.HostPackagesRootDir,
		OS:        facts.OS,
		OSVersion: facts.OSVersion,
		Arch:      facts.Arch,
	})
	if err != nil {
		rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: install host packages: %w", err), rollback)
		checks = append(checks, rollbackChecks...)
		return nil, checks, failErr
	}
	checks = append(checks, evidence.Check{
		ID: "host-packages-installed", Category: "host", Status: evidence.StatusPass,
		Message:   fmt.Sprintf("installed offline host packages from %s for day-2 mDNS, client Wi-Fi, and Wi-Fi AP (services remain off until enabled via API)", resolved.HostPackagesRootDir),
		Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	})

	prepared, err := helm.EnsureReleasePrereqs(ctx, o.HelmRun, opts.KubeconfigPath, helm.ChartRelease{
		Name:       opts.ChartReleaseName,
		ChartPath:  chartPath,
		Namespace:  opts.ChartNamespace,
		ValuesPath: preparedValuesPath,
	})
	checks = append(checks, prepared.Checks...)
	if err != nil {
		rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", err), func() []evidence.Check {
			_ = importer.Rollback(ctx, preloadResult.NewlyImported)
			return rollback()
		})
		checks = append(checks, rollbackChecks...)
		return nil, checks, failErr
	}

	if err := helm.EnsureNamespace(ctx, o.HelmRun, opts.KubeconfigPath, productconfig.ControlPlaneAppsNamespace, nil); err != nil {
		rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: prepare apps namespace %s: %w", productconfig.ControlPlaneAppsNamespace, err), func() []evidence.Check {
			_ = importer.Rollback(ctx, preloadResult.NewlyImported)
			return rollback()
		})
		checks = append(checks, rollbackChecks...)
		return nil, checks, failErr
	}

	if err := helm.EnsureNamespace(ctx, o.HelmRun, opts.KubeconfigPath, productconfig.ApplicationNamespace, helm.RestrictedNamespaceLabels()); err != nil {
		rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: prepare application namespace %s: %w", productconfig.ApplicationNamespace, err), func() []evidence.Check {
			_ = importer.Rollback(ctx, preloadResult.NewlyImported)
			return rollback()
		})
		checks = append(checks, rollbackChecks...)
		return nil, checks, failErr
	}

	keysReplica, keysReplicaErr := helm.EnsureKeysSecretReplica(ctx, o.HelmRun, opts.KubeconfigPath,
		opts.ChartNamespace, productconfig.ControlPlaneAppsNamespace, "appliance-keys")
	checks = append(checks, keysReplica.Checks...)
	if keysReplicaErr != nil {
		rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", keysReplicaErr), func() []evidence.Check {
			_ = keysReplica.Cleanup()
			_ = importer.Rollback(ctx, preloadResult.NewlyImported)
			return rollback()
		})
		checks = append(checks, rollbackChecks...)
		return nil, checks, failErr
	}

	if strings.TrimSpace(opts.ImagePullRegistry.Registry) != "" {
		if err := productconfig.InjectImagePullSecrets(preparedValuesPath, productconfig.ImagePullSecretName); err != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: inject image-pull secrets into values: %w", err), func() []evidence.Check {
				_ = keysReplica.Cleanup()
				_ = importer.Rollback(ctx, preloadResult.NewlyImported)
				return rollback()
			})
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
		for _, valuesPath := range []string{registryValuesPath, dnsValuesPath, inferenceValuesPath, videoValuesPath} {
			if strings.TrimSpace(valuesPath) == "" {
				continue
			}
			if err := productconfig.InjectImagePullSecrets(valuesPath, productconfig.ImagePullSecretName); err != nil {
				rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: inject image-pull secrets into %s: %w", valuesPath, err), func() []evidence.Check {
					_ = keysReplica.Cleanup()
					_ = importer.Rollback(ctx, preloadResult.NewlyImported)
					return rollback()
				})
				checks = append(checks, rollbackChecks...)
				return nil, checks, failErr
			}
		}
		imagePullSecrets, imagePullErr := helm.EnsureImagePullSecrets(ctx, o.HelmRun, opts.KubeconfigPath, opts.ImagePullRegistry,
			productconfig.ProductNamespaces(opts.ChartNamespace)...)
		checks = append(checks, imagePullSecrets.Checks...)
		if imagePullErr != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", imagePullErr), func() []evidence.Check {
				_ = imagePullSecrets.Cleanup()
				_ = keysReplica.Cleanup()
				_ = importer.Rollback(ctx, preloadResult.NewlyImported)
				return rollback()
			})
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
	}

	tlsPrepared, tlsErr := helm.EnsureApplianceTLSSecrets(ctx, o.HelmRun, opts.KubeconfigPath, helm.ApplianceTLSOptions{
		ControlNamespace:  opts.ChartNamespace,
		ArtifactNamespace: registryNamespace,
		IncludeArtifacts:  targetArtifact,
		FQDN:              identity.FQDN,
		NodeIPv4:          nodeIPv4,
		ExtraSANs:         tlsSANs,
	})
	checks = append(checks, tlsPrepared.Checks...)
	if tlsErr != nil {
		rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", tlsErr), func() []evidence.Check {
			_ = tlsPrepared.Cleanup()
			_ = importer.Rollback(ctx, preloadResult.NewlyImported)
			return rollback()
		})
		checks = append(checks, rollbackChecks...)
		return nil, checks, failErr
	}

	readinessChecks, err := helm.EnsureClusterBaseline(ctx, o.HelmRun, opts.KubeconfigPath, preparedValuesPath)
	checks = append(checks, readinessChecks...)
	if err != nil {
		rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", err), func() []evidence.Check {
			_ = importer.Rollback(ctx, preloadResult.NewlyImported)
			return rollback()
		})
		checks = append(checks, rollbackChecks...)
		return nil, checks, failErr
	}
	traefikLBCheck, traefikLBErr := helm.EnsureTraefikManagementExternalIPs(ctx, o.HelmRun, opts.KubeconfigPath)
	checks = append(checks, traefikLBCheck)
	if traefikLBErr != nil {
		rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", traefikLBErr), func() []evidence.Check {
			_ = importer.Rollback(ctx, preloadResult.NewlyImported)
			return rollback()
		})
		checks = append(checks, rollbackChecks...)
		return nil, checks, failErr
	}
	traefikTimeoutCheck, traefikTimeoutErr := helm.EnsureTraefikTransferTimeouts(ctx, o.HelmRun, opts.KubeconfigPath)
	checks = append(checks, traefikTimeoutCheck)
	if traefikTimeoutErr != nil {
		rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", traefikTimeoutErr), func() []evidence.Check {
			_ = importer.Rollback(ctx, preloadResult.NewlyImported)
			return rollback()
		})
		checks = append(checks, rollbackChecks...)
		return nil, checks, failErr
	}

	applier := &helm.Applier{Run: o.HelmRun, Kubeconfig: opts.KubeconfigPath}
	if resolved.MessageBrokerChartPath != "" {
		messageBrokerCheck, messageBrokerErr := applier.InstallOrUpgrade(ctx, helm.ChartRelease{Name: messageBrokerReleaseName, ChartPath: resolved.MessageBrokerChartPath, Namespace: messageBrokerNamespace})
		checks = append(checks, messageBrokerCheck)
		if messageBrokerErr != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: message broker: %w", messageBrokerErr), rollback)
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
	}
	if hadWorkflowsBefore && !targetWorkflows {
		if err := applier.Uninstall(ctx, workflowsReleaseName); err != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: remove workflows capability: %w", err), rollback)
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
	}
	for _, dir := range hostdirs.ServiceLogDirs(targetArtifact, targetFiles, targetWorkflows, targetDNS, targetInference, targetVideo) {
		if err := o.EnsureOwnedDir(dir.Path, dir.UID, dir.GID, dir.Mode); err != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: prepare service log directory %s: %w", dir.Path, err), rollback)
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
		checks = append(checks, evidence.Check{
			ID: dir.CheckID, Category: "host", Status: evidence.StatusPass,
			Message:   fmt.Sprintf("%s owned by %d:%d", dir.Path, dir.UID, dir.GID),
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
	}
	for _, file := range hostdirs.ServiceLogFiles(targetArtifact, targetFiles, targetWorkflows, targetDNS, targetInference, targetVideo) {
		if o.EnsureOwnedFile == nil {
			continue
		}
		if err := o.EnsureOwnedFile(file.Path, file.UID, file.GID, file.Mode); err != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: prepare service log file %s: %w", file.Path, err), rollback)
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
		checks = append(checks, evidence.Check{
			ID: file.CheckID, Category: "host", Status: evidence.StatusPass,
			Message:   fmt.Sprintf("%s owned by %d:%d mode %04o", file.Path, file.UID, file.GID, file.Mode.Perm()),
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
	}
	if targetHost {
		installHostAgent := o.InstallHostAgent
		if installHostAgent == nil {
			installHostAgent = func(hostagent.InstallSpec) (func() error, error) {
				return func() error { return nil }, nil
			}
		}
		hostAgentRollback, err = installHostAgent(hostagent.InstallSpec{
			SourceBinaryPath: resolved.HostAgentBinaryPath,
			BinaryDestPath:   opts.HostAgentBinaryDestPath,
			UnitPath:         opts.HostAgentUnitPath,
			UnitName:         opts.HostAgentUnitName,
			SocketPath:       opts.HostAgentSocketPath,
			LogPath:          opts.HostAgentLogPath,
		})
		if err != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: install host agent: %w", err), rollback)
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
		checks = append(checks, evidence.Check{
			ID: "host-agent-installed", Category: "host", Status: evidence.StatusPass,
			Message:   fmt.Sprintf("host agent installed at %s and running via %s", opts.HostAgentBinaryDestPath, opts.HostAgentUnitName),
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
		// Wi-Fi AP apply is deferred until after appliance-dns (when the landns
		// capability is on the profile) so CoreDNS owns host :53 first and the
		// AP bind-probe falls back to DHCP-only DNS mode for manage.ap.
	}
	if targetArtifact {
		registryKeys, keyErr := helm.EnsureRegistryPublicKeySecret(ctx, o.HelmRun, opts.KubeconfigPath,
			opts.ChartNamespace, "appliance-keys", registryNamespace, productconfig.DefaultRegistryPublicKeySecret)
		checks = append(checks, registryKeys.Checks...)
		if keyErr != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", keyErr), rollback)
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
		registryCheck, registryErr := applier.InstallOrUpgrade(ctx, helm.ChartRelease{
			Name: registryReleaseName, ChartPath: resolved.RegistryChartPath, Namespace: registryNamespace, ValuesPath: registryValuesPath,
		})
		checks = append(checks, registryCheck)
		if registryErr != nil {
			checks = append(checks, helm.CollectFailureDiagnostics(ctx, o.HelmRun, opts.KubeconfigPath, helm.ChartRelease{
				Name:       registryReleaseName,
				ChartPath:  resolved.RegistryChartPath,
				Namespace:  registryNamespace,
				ValuesPath: registryValuesPath,
			})...)
			registryWasFreshInstall := !hadArtifactBefore
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", registryErr), func() []evidence.Check {
				_ = registryKeys.Cleanup()
				if registryWasFreshInstall {
					_ = applier.Uninstall(ctx, registryReleaseName)
				} else {
					_ = applier.Rollback(ctx, registryReleaseName, false)
				}
				return rollback()
			})
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
	}
	if targetDNS {
		// Free :53 immediately before DNS Helm so early upgrade validation
		// failures do not leave systemd-resolved reconfigured. Only roll the
		// host change back when this upgrade is newly adding DNS.
		if o.PrepareHostDNS != nil {
			hostname := strings.TrimSpace(opts.NodeName)
			if hostname == "" {
				if h, err := os.Hostname(); err == nil {
					hostname = strings.TrimSpace(h)
				}
			}
			prep, prepErr := o.PrepareHostDNS(hostdns.PrepareConfig{
				Hostname: hostname,
				IPv4:     nodeIPv4,
				Aliases:  append([]string(nil), tlsSANs...),
			})
			if prepErr != nil {
				rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: prepare host for LAN DNS on port 53: %w", prepErr), rollback)
				checks = append(checks, rollbackChecks...)
				return nil, checks, failErr
			}
			if prep.Changed && !hadDNSBefore {
				restoreHostDNSOnRollback = true
				checks = append(checks, evidence.Check{
					ID: "host-dns-stub-disabled", Category: "host", Status: evidence.StatusPass,
					Message:   "prepared host for LAN DNS (systemd-resolved stub disabled and/or node hostname seeded in /etc/hosts)",
					Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
				})
			}
		}
		if err := hostpackages.QuiesceStockDaemonUnits(); err != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: free port 53 from stock DNS packages: %w", err), rollback)
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
		dnsCheck, dnsErr := applier.InstallOrUpgrade(ctx, helm.ChartRelease{
			Name: dnsReleaseName, ChartPath: resolved.DNSChartPath, Namespace: dnsNamespace, ValuesPath: dnsValuesPath,
			NamespaceLabels: helm.PrivilegedNamespaceLabels(),
		})
		checks = append(checks, dnsCheck)
		if dnsErr != nil {
			checks = append(checks, helm.CollectFailureDiagnostics(ctx, o.HelmRun, opts.KubeconfigPath, helm.ChartRelease{
				Name:       dnsReleaseName,
				ChartPath:  resolved.DNSChartPath,
				Namespace:  dnsNamespace,
				ValuesPath: dnsValuesPath,
			})...)
			dnsWasFreshInstall := !hadDNSBefore
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", dnsErr), func() []evidence.Check {
				if dnsWasFreshInstall {
					_ = applier.Uninstall(ctx, dnsReleaseName)
				} else {
					_ = applier.Rollback(ctx, dnsReleaseName, false)
				}
				return rollback()
			})
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
	}
	if targetInference {
		inferenceCheck, inferenceErr := applier.InstallOrUpgrade(ctx, helm.ChartRelease{
			Name: inferenceReleaseName, ChartPath: resolved.InferenceChartPath, Namespace: inferenceNamespace, ValuesPath: inferenceValuesPath,
			NamespaceLabels: helm.RestrictedNamespaceLabels(),
		})
		checks = append(checks, inferenceCheck)
		if inferenceErr != nil {
			checks = append(checks, helm.CollectFailureDiagnostics(ctx, o.HelmRun, opts.KubeconfigPath, helm.ChartRelease{
				Name:       inferenceReleaseName,
				ChartPath:  resolved.InferenceChartPath,
				Namespace:  inferenceNamespace,
				ValuesPath: inferenceValuesPath,
			})...)
			inferenceWasFreshInstall := !hadInferenceBefore
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", inferenceErr), func() []evidence.Check {
				if inferenceWasFreshInstall {
					_ = applier.Uninstall(ctx, inferenceReleaseName)
				} else {
					_ = applier.Rollback(ctx, inferenceReleaseName, false)
				}
				return rollback()
			})
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
	}
	if targetVideo {
		videoCheck, videoErr := applier.InstallOrUpgrade(ctx, helm.ChartRelease{
			Name: videoReleaseName, ChartPath: resolved.VideoChartPath, Namespace: videoNamespace, ValuesPath: videoValuesPath,
			NamespaceLabels: helm.RestrictedNamespaceLabels(),
		})
		checks = append(checks, videoCheck)
		if videoErr != nil {
			checks = append(checks, helm.CollectFailureDiagnostics(ctx, o.HelmRun, opts.KubeconfigPath, helm.ChartRelease{
				Name:       videoReleaseName,
				ChartPath:  resolved.VideoChartPath,
				Namespace:  videoNamespace,
				ValuesPath: videoValuesPath,
			})...)
			videoWasFreshInstall := !hadVideoBefore
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", videoErr), func() []evidence.Check {
				if videoWasFreshInstall {
					_ = applier.Uninstall(ctx, videoReleaseName)
				} else {
					_ = applier.Rollback(ctx, videoReleaseName, false)
				}
				return rollback()
			})
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
	}
	if targetWorkflows {
		for _, crdPath := range resolved.WorkflowsCRDPaths {
			if _, applyErr := o.HelmRun(ctx, "kubectl", "--kubeconfig", opts.KubeconfigPath, "apply", "-f", crdPath); applyErr != nil {
				rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: apply workflows CRD %s: %w", crdPath, applyErr), rollback)
				checks = append(checks, rollbackChecks...)
				return nil, checks, failErr
			}
		}
		if resolved.WorkflowsChartPath != "" {
			workflowsCheck, workflowsErr := applier.InstallOrUpgrade(ctx, helm.ChartRelease{
				Name: workflowsReleaseName, ChartPath: resolved.WorkflowsChartPath, Namespace: workflowsNamespace,
			})
			checks = append(checks, workflowsCheck)
			if workflowsErr != nil {
				rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", workflowsErr), func() []evidence.Check {
					_ = applier.Rollback(ctx, workflowsReleaseName, false)
					return rollback()
				})
				checks = append(checks, rollbackChecks...)
				return nil, checks, failErr
			}
		}
	}
	chartCheck, err := applier.InstallOrUpgrade(ctx, helm.ChartRelease{
		Name:       opts.ChartReleaseName,
		ChartPath:  chartPath,
		Namespace:  opts.ChartNamespace,
		ValuesPath: preparedValuesPath,
	})
	checks = append(checks, chartCheck)
	if err != nil {
		checks = append(checks, helm.CollectFailureDiagnostics(ctx, o.HelmRun, opts.KubeconfigPath, helm.ChartRelease{
			Name:       opts.ChartReleaseName,
			ChartPath:  chartPath,
			Namespace:  opts.ChartNamespace,
			ValuesPath: preparedValuesPath,
		})...)
		rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", err), func() []evidence.Check {
			_ = prepared.Cleanup()
			_ = applier.Rollback(ctx, opts.ChartReleaseName, false)
			_ = importer.Rollback(ctx, preloadResult.NewlyImported)
			return rollback()
		})
		checks = append(checks, rollbackChecks...)
		return nil, checks, failErr
	}

	// Re-attach image-pull secrets after charts may have created new SAs.
	if strings.TrimSpace(opts.ImagePullRegistry.Registry) != "" {
		reconcilePull, reconcileErr := helm.EnsureImagePullSecrets(ctx, o.HelmRun, opts.KubeconfigPath, opts.ImagePullRegistry,
			productconfig.ProductNamespaces(opts.ChartNamespace)...)
		checks = append(checks, reconcilePull.Checks...)
		if reconcileErr != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: reconcile image-pull secrets: %w", reconcileErr), func() []evidence.Check {
				_ = prepared.Cleanup()
				_ = applier.Rollback(ctx, opts.ChartReleaseName, false)
				_ = importer.Rollback(ctx, preloadResult.NewlyImported)
				return rollback()
			})
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
	}

	zonctlRollback, err := zonctlhost.Install(zonctlhost.InstallSpec{
		SourceBinaryPath:  resolved.ZonctlBinaryPath,
		RealDestPath:      opts.ZonctlRealDestPath,
		LauncherDestPath:  opts.ZonctlLauncherDestPath,
		HelperSourcePaths: resolved.HelperBinaryPaths,
	})
	if err != nil {
		rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: install host zonctl: %w", err), func() []evidence.Check {
			_ = prepared.Cleanup()
			_ = applier.Rollback(ctx, opts.ChartReleaseName, false)
			_ = importer.Rollback(ctx, preloadResult.NewlyImported)
			return rollback()
		})
		checks = append(checks, rollbackChecks...)
		return nil, checks, failErr
	}

	now := time.Now().UTC()
	updated := &state.InstalledState{
		SchemaVersion:       1,
		ApplianceInstanceID: installed.ApplianceInstanceID,
		InstalledVersion:    targetVersion,
		InstalledReleaseID:  resolved.ReleaseID,
		ApplianceProfile:    effectiveProfile,
		ApplianceName:       identity.Name,
		DNSZone:             identity.Zone,
		Components: state.Components{
			K3sVersion:            resolved.Compatibility.K3sVersion,
			ChartVersion:          resolved.Compatibility.ChartVersion,
			ArtifactServerVersion: resolved.ArtifactServerComponentVersion(resolved.Compatibility.ArtifactServerVersion),
			DNSVersion:            resolved.DNSComponentVersion(resolved.Compatibility.DNSVersion),
			InferenceVersion:      resolved.InferenceComponentVersion(resolved.Compatibility.InferenceVersion),
			VideoVersion:          resolved.VideoComponentVersion(resolved.Compatibility.VideoVersion),
			MetadataVersion:       metadataVersion,
			MetadataDigest:        metadataDigest,
		},
		K3sOwnership: state.K3sOwnership{Owned: true, OwnerApplianceVersion: targetVersion},
		LastOperation: state.Operation{
			Type:          "upgrade",
			Status:        "completed",
			TransactionID: opts.TransactionID,
			StartedAt:     now,
			CompletedAt:   &now,
			SourceVersion: installed.InstalledVersion,
			TargetVersion: targetVersion,
		},
		CreatedAt: installed.CreatedAt,
		UpdatedAt: now,
	}
	if err := state.Save(opts.InstalledStatePath, updated); err != nil {
		rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", err), func() []evidence.Check {
			_ = zonctlRollback()
			_ = prepared.Cleanup()
			_ = applier.Rollback(ctx, opts.ChartReleaseName, false)
			_ = importer.Rollback(ctx, preloadResult.NewlyImported)
			return rollback()
		})
		checks = append(checks, rollbackChecks...)
		return nil, checks, failErr
	}

	return updated, checks, nil
}

// preferredUpgradeLocalIPv4 mirrors internal/install's preferredLocalIPv4:
// the first candidate that parses as a literal IPv4 address seeds LAN
// DNS NS glue IPv4 on upgrade too, so re-running with the same
// host options keeps producing the same record.
// withApplianceFQDN puts the derived appliance FQDN first in the TLS SAN list
// and deduplicates subsequent entries.
func withApplianceFQDN(fqdn string, sans ...string) []string {
	fqdn = strings.TrimSpace(fqdn)
	out := make([]string, 0, len(sans)+1)
	seen := map[string]struct{}{}
	appendUnique := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	appendUnique(fqdn)
	for _, san := range sans {
		appendUnique(san)
	}
	return out
}

func preferredUpgradeLocalIPv4(candidates ...string) string {
	return hostdns.PreferredLocalIPv4(candidates...)
}

func firstUpgradeString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func writeImagePullRegistries(ops k3s.Ops, opts Options) error {
	if strings.TrimSpace(opts.ImagePullRegistry.Registry) == "" {
		return nil
	}
	path := strings.TrimSpace(opts.K3sRegistriesPath)
	if path == "" {
		return fmt.Errorf("upgrade: image pull registry configured but K3sRegistriesPath is empty")
	}
	cfg := opts.ImagePullRegistry
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("upgrade: image pull registry: %w", err)
	}
	if ops.WriteRegistries == nil {
		return fmt.Errorf("upgrade: WriteRegistries is not configured")
	}
	if err := ops.WriteRegistries(path, cfg); err != nil {
		return fmt.Errorf("upgrade: write k3s registries.yaml: %w", err)
	}
	return nil
}

// snapshotFile copies path to path+".previous", overwriting any prior
// snapshot, so a failed upgrade can restore exactly what was there
// before this attempt.
func snapshotFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("snapshot %s: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("snapshot %s: %w", path, err)
	}
	return os.WriteFile(path+".previous", data, info.Mode())
}

// revertFile restores path from its ".previous" snapshot written by
// snapshotFile.
func revertFile(path string) error {
	src, err := os.Open(path + ".previous")
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(path)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}
