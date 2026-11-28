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
	"github.com/zoncaesaradmin/appliance-ctl/internal/cloudflared"
	"github.com/zoncaesaradmin/appliance-ctl/internal/cluster"
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
	"github.com/zoncaesaradmin/appliance-ctl/internal/nvidia"
	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
	"github.com/zoncaesaradmin/appliance-ctl/internal/runtimeconfig"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
	"github.com/zoncaesaradmin/appliance-ctl/internal/zonctlhost"
)

// Options fully parameterizes an upgrade. Every path is explicit, as in
// internal/install, so tests can redirect every mutating operation.
// Target release artifact resolution is the caller's install.Source, not
// part of Options.
type Options struct {
	TargetApplianceVersion string

	InstalledStatePath            string
	K3sConfigPath                 string
	K3sUnitPath                   string
	K3sBinaryDestPath             string
	K3sUnitName                   string
	K3sDataDir                    string
	KubeconfigPath                string
	HostAgentBinaryDestPath       string
	HostAgentUnitPath             string
	HostAgentUnitName             string
	HostAgentSocketPath           string
	HostAgentLogPath              string
	CloudflaredTunnelTokenPath    string
	CloudflaredBinaryDestPath     string
	CloudflaredUnitPath           string
	CloudflaredUnitName           string
	CloudflaredTokenDestPath      string
	ApplianceProfile              string
	PublicOrigin                  string
	ChannelIntegrationOrigin      string
	TLSTermination                string
	TLSCertificatePath            string
	TLSKeyPath                    string
	TLSSecretName                 string
	ChannelIntegrationRuntimePath string
	// AuthServiceOTPDeliveryMode overrides the production-default event
	// delivery mode for development/test upgrades. Empty selects event.
	AuthServiceOTPDeliveryMode string
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
	messageBrokerReleaseName = "message-broker"
	messageBrokerNamespace   = "ace-system"
	registryNamespace        = "artifacts"
	dnsReleaseName           = "appliance-dns"
	dnsNamespace             = "dns"
	inferenceReleaseName     = "appliance-inference"
	inferenceNamespace       = "inference"
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
	InstallCloudflared  func(cloudflared.InstallSpec) (func() error, error)
	InstallHostPackages func(hostpackages.InstallSpec) (func() error, error)
	// EnsureMDNSEnabled and EnsureMDNSDisabled converge host mDNS with the
	// target profile's lan-discovery capability after the host agent refresh.
	EnsureMDNSEnabled  func(context.Context, string, string) error
	EnsureMDNSDisabled func(context.Context, string) error
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
		InstallCloudflared:  cloudflared.InstallOrUpdate,
		InstallHostPackages: hostpackages.InstallRequiredPackages,
		EnsureMDNSEnabled:   hostagent.EnsureMDNSEnabled,
		EnsureMDNSDisabled:  hostagent.EnsureMDNSDisabled,
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
// Coordinating product migration hooks
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
	if resolved.Compatibility.DeploymentTopology == state.DeploymentTopologyEmbeddedEtcdV1 {
		return nil, checks, fmt.Errorf("upgrade: signed embedded-etcd-v1 release requires a coordinated recovery and rolling-upgrade coordinator")
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
	hadArtifactBefore := productconfig.HasCapabilityInCatalog(installed.ApplianceProfile, productconfig.CapabilityArtifact, resolved.ProfileCatalog)
	hadFilesBefore := productconfig.HasCapabilityInCatalog(installed.ApplianceProfile, productconfig.CapabilityFiles, resolved.ProfileCatalog)
	hadDNSBefore := productconfig.HasCapabilityInCatalog(installed.ApplianceProfile, productconfig.CapabilityDNS, resolved.ProfileCatalog)
	hadInferenceBefore := productconfig.HasCapabilityInCatalog(installed.ApplianceProfile, productconfig.CapabilityInference, resolved.ProfileCatalog)
	targetArtifact := resolved.ArtifactEnabled
	targetFiles := resolved.FilesEnabled
	targetDNS := resolved.DNSEnabled
	targetInference := resolved.InferenceEnabled
	if previous, ok := installed.Runtimes["inference"]; ok && targetInference && !runtimeconfig.Equal(previous, resolved.Runtimes["inference"]) {
		return nil, checks, fmt.Errorf("upgrade: inference package/engine changes require an explicit supported migration")
	}
	targetLANDiscovery := resolved.LANDiscoveryEnabled
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
	tlsTermination := strings.ToLower(strings.TrimSpace(opts.TLSTermination))
	if tlsTermination == "" {
		tlsTermination = "traefik"
	}
	if (strings.TrimSpace(opts.TLSCertificatePath) == "") != (strings.TrimSpace(opts.TLSKeyPath) == "") {
		return nil, checks, fmt.Errorf("upgrade: public TLS certificate and key must be supplied together")
	}
	if tlsTermination == "cloudflare" && (strings.TrimSpace(opts.TLSCertificatePath) != "" || strings.TrimSpace(opts.TLSKeyPath) != "") {
		return nil, checks, fmt.Errorf("upgrade: public TLS certificate/key are for direct Traefik TLS; omit them with cloudflare termination")
	}
	if resolved.ChannelIntegrationsEnabled || resolved.ApplicationIdentityEnabled || resolved.ApplicationAuthEnabled {
		if strings.TrimSpace(opts.PublicOrigin) == "" {
			return nil, checks, fmt.Errorf("upgrade: application-facing capabilities require --public-origin")
		}
		if tlsTermination != "cloudflare" && tlsTermination != "traefik" {
			return nil, checks, fmt.Errorf("upgrade: tls termination must be traefik or cloudflare")
		}
		if tlsTermination == "cloudflare" && strings.TrimSpace(opts.CloudflaredTunnelTokenPath) == "" {
			return nil, checks, fmt.Errorf("upgrade: cloudflare TLS termination requires --cloudflare-tunnel-token-file")
		}
		if tlsTermination == "traefik" && strings.TrimSpace(opts.CloudflaredTunnelTokenPath) != "" {
			return nil, checks, fmt.Errorf("upgrade: --cloudflare-tunnel-token-file requires --tls-termination cloudflare")
		}
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
	if selected, ok := resolved.Runtimes["inference"]; ok {
		if err := runtimeconfig.ValidateTargetArchitecture(selected, facts.Arch); err != nil {
			return nil, checks, fmt.Errorf("upgrade: %w", err)
		}
		checks = append(checks, evidence.Check{
			ID: "inference-runtime-architecture-match", Category: "host", Status: evidence.StatusPass,
			Message:   fmt.Sprintf("inference package %s targets host architecture %s", selected.Package, facts.Arch),
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
	}
	// Always include the derived FQDN even when the CLI computed TLSSANs before
	// installed-state identity was known (omitted --appliance-name/--dns-zone).
	tlsSANs := withApplianceFQDN(identity.FQDN, opts.TLSSANs...)
	nodeIPv4 := preferredUpgradeLocalIPv4(tlsSANs...)
	selectedInferenceRuntime := resolved.Runtimes["inference"]
	webUIEnabled := productconfig.HasCapabilityInCatalog(effectiveProfile, productconfig.CapabilityOpenWebUI, resolved.ProfileCatalog) &&
		resolved.OpenWebUIImageReference != "" && resolved.OpenWebUIGatewayImageReference != ""
	openWebUIImageReference := ""
	openWebUIGatewayImageReference := ""
	if webUIEnabled {
		openWebUIImageReference = resolved.OpenWebUIImageReference
		openWebUIGatewayImageReference = resolved.OpenWebUIGatewayImageReference
	}
	preparedValuesPath, cleanupPreparedValues, err := productconfig.PrepareValuesFileForRuntimeWithPublicOriginsAndAuthDeliveryModeAndModules(
		resolved.ConfigurationPath, effectiveProfile, resolved.ProfileCatalog,
		resolved.Modules,
		resolved.HostAgentImageReference,
		identity.Name, identity.Zone, nodeIPv4, selectedInferenceRuntime,
		webUIEnabled, opts.PublicOrigin, opts.ChannelIntegrationOrigin, opts.TLSTermination, opts.AuthServiceOTPDeliveryMode,
		resolved.ArtifactServerImageReference, resolved.BlobStorageImageReference, resolved.PostgresImageReference, resolved.ChannelIntegrationImageReference, resolved.OrderingImageReference, resolved.ApplicationIdentityImageReference, resolved.AuthServiceImageReference, resolved.PostGISImageReference,
	)
	if err != nil {
		return nil, checks, fmt.Errorf("upgrade: %w", err)
	}
	defer cleanupPreparedValues()
	if err := productconfig.InjectTLSSecretName(preparedValuesPath, opts.TLSSecretName); err != nil {
		return nil, checks, fmt.Errorf("upgrade: configure TLS Secret name: %w", err)
	}
	if err := productconfig.InjectPlacementNodeName(preparedValuesPath, opts.NodeName); err != nil {
		return nil, checks, fmt.Errorf("upgrade: %w", err)
	}
	registryValuesPath := ""
	cleanupRegistryValues := func() {}
	if targetArtifact {
		registryValuesPath, cleanupRegistryValues, err = productconfig.PrepareRegistryValuesFile(filepath.Dir(resolved.ConfigurationPath), resolved.ArtifactServerImageReference, identity.FQDN)
		if err != nil {
			return nil, checks, fmt.Errorf("upgrade: %w", err)
		}
		defer cleanupRegistryValues()
		if err := productconfig.InjectRegistryTLSSecretName(registryValuesPath, opts.TLSSecretName); err != nil {
			return nil, checks, fmt.Errorf("upgrade: configure registry TLS Secret: %w", err)
		}
		if err := productconfig.InjectPlacementNodeName(registryValuesPath, opts.NodeName); err != nil {
			return nil, checks, fmt.Errorf("upgrade: %w", err)
		}
	}
	dnsValuesPath := ""
	cleanupDNSValues := func() {}
	if targetDNS {
		dnsValuesPath, cleanupDNSValues, err = productconfig.PrepareDNSValuesFile(filepath.Dir(resolved.ConfigurationPath), resolved.DNSImageReference, identity.Zone, nodeIPv4)
		if err != nil {
			return nil, checks, fmt.Errorf("upgrade: %w", err)
		}
		defer cleanupDNSValues()
		if err := productconfig.InjectPlacementNodeName(dnsValuesPath, opts.NodeName); err != nil {
			return nil, checks, fmt.Errorf("upgrade: %w", err)
		}
	}
	inferenceValuesPath := ""
	cleanupInferenceValues := func() {}
	if targetInference {
		inferenceValuesPath, cleanupInferenceValues, err = productconfig.PrepareInferenceValuesFileForNode(filepath.Dir(resolved.ConfigurationPath), resolved.InferenceImageReference, resolved.InferenceManagerImageReference, openWebUIImageReference, openWebUIGatewayImageReference, resolved.Runtimes["inference"], opts.NodeName)
		if err != nil {
			return nil, checks, fmt.Errorf("upgrade: %w", err)
		}
		defer cleanupInferenceValues()
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
	if err := o.EnsureOwnedDir(hostdirs.BlobStorageDir, hostdirs.BlobStorageDirOwnerUID, hostdirs.ApplianceSharedFSGID, hostdirs.WorkspaceDirMode); err != nil {
		return nil, checks, fmt.Errorf("upgrade: prepare blob storage directory: %w", err)
	}
	checks = append(checks, evidence.Check{
		ID: "blob-storage-directory-owned", Category: "host", Status: evidence.StatusPass,
		Message:   fmt.Sprintf("%s owned by %d:%d", hostdirs.BlobStorageDir, hostdirs.BlobStorageDirOwnerUID, hostdirs.ApplianceSharedFSGID),
		Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	})
	metadataBundlesDir := strings.TrimSpace(opts.MetadataBundlesDir)
	if metadataBundlesDir == "" {
		metadataBundlesDir = hostdirs.MetadataBundlesDir
	}
	if err := o.EnsureOwnedDir(metadataBundlesDir, hostdirs.ActionRuntimeDirOwnerUID, hostdirs.ApplianceSharedFSGID, hostdirs.SharedWritableDirMode); err != nil {
		return nil, checks, fmt.Errorf("upgrade: prepare metadata-bundles directory: %w", err)
	}
	checks = append(checks, evidence.Check{
		ID: "metadata-bundles-directory-owned", Category: "host", Status: evidence.StatusPass,
		Message:   fmt.Sprintf("%s owned by %d:%d", metadataBundlesDir, hostdirs.ActionRuntimeDirOwnerUID, hostdirs.ApplianceSharedFSGID),
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
	// The legacy upgrade rollback takes a K3s-directory snapshot. PostgreSQL
	// deliberately lives outside that directory, so proceeding would advertise
	// a rollback guarantee that cannot restore the control-plane database.
	if install.DatabaseEngine(resolved) == "postgres" {
		return nil, checks, fmt.Errorf("upgrade: PostgreSQL recovery-set backup is not yet implemented; refusing upgrade because legacy rollback would omit the control-plane database")
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
	var cloudflaredRollback func() error
	var channelRuntimeRollback func() error
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
		if cloudflaredRollback != nil {
			if err := cloudflaredRollback(); err != nil {
				rollbackErrs = append(rollbackErrs, err)
			}
		}
		if channelRuntimeRollback != nil {
			if err := channelRuntimeRollback(); err != nil {
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
	{
		if resolved.HostPackagesRootDir == "" {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: foundation mDNS requires host-packages"), rollback)
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
		installHostPackages := o.InstallHostPackages
		if installHostPackages == nil {
			installHostPackages = func(hostpackages.InstallSpec) (func() error, error) {
				return func() error { return nil }, nil
			}
		}
		serviceName := ""
		if targetLANDiscovery {
			serviceName = hostpackages.MDNSServiceName
		}
		hostPackagesRollback, err = installHostPackages(hostpackages.InstallSpec{
			RootDir: resolved.HostPackagesRootDir, OS: facts.OS, OSVersion: facts.OSVersion, Arch: facts.Arch,
			ServiceName: serviceName,
		})
		if err != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: install host packages: %w", err), rollback)
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
		checks = append(checks, evidence.Check{
			ID: "host-packages-installed", Category: "host", Status: evidence.StatusPass,
			Message:   fmt.Sprintf("installed offline host packages from %s for foundation mDNS; Wi-Fi services remain off until enabled via host APIs", resolved.HostPackagesRootDir),
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
	}

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

	// Keep the shared application prerequisites namespace present before the
	// chart upgrade renders any application workloads. The fresh-install path
	// applies the dedicated ace-app-core release between ace-infra/ace-system
	// and ace-apps; upgrades preserve that namespace boundary.
	if err := helm.EnsureNamespace(ctx, o.HelmRun, opts.KubeconfigPath, productconfig.ApplicationCoreNamespace, helm.RestrictedNamespaceLabels()); err != nil {
		rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: prepare application-core namespace %s: %w", productconfig.ApplicationCoreNamespace, err), func() []evidence.Check {
			_ = importer.Rollback(ctx, preloadResult.NewlyImported)
			return rollback()
		})
		checks = append(checks, rollbackChecks...)
		return nil, checks, failErr
	}
	if resolved.PostgresImageReference != "" && (resolved.ApplicationAuthEnabled || resolved.ApplicationIdentityEnabled || resolved.CommerceEnabled) {
		databaseCoreReplica, databaseCoreErr := helm.EnsureControlPlaneDatabaseConnectionReplica(ctx, o.HelmRun, opts.KubeconfigPath,
			productconfig.InfrastructureNamespace, productconfig.ApplicationCoreNamespace, "controlplane-database-connection")
		checks = append(checks, databaseCoreReplica.Checks...)
		if databaseCoreErr != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", databaseCoreErr), func() []evidence.Check {
				_ = databaseCoreReplica.Cleanup()
				return rollback()
			})
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
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

	if resolved.ApplicationIdentityEnabled {
		identitySecret, identityErr := helm.EnsureApplicationIdentitySecret(ctx, o.HelmRun, opts.KubeconfigPath, productconfig.ControlPlaneAppsNamespace, "application-identity-secrets")
		checks = append(checks, identitySecret.Checks...)
		if identityErr != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", identityErr), func() []evidence.Check {
				_ = identitySecret.Cleanup()
				_ = keysReplica.Cleanup()
				_ = importer.Rollback(ctx, preloadResult.NewlyImported)
				return rollback()
			})
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
	}
	if resolved.ApplicationAuthEnabled {
		var authSecret helm.PreparedRelease
		var authErr error
		if resolved.ApplicationIdentityEnabled {
			authSecret, authErr = helm.EnsureApplicationAuthSecretReplica(ctx, o.HelmRun, opts.KubeconfigPath, productconfig.ControlPlaneAppsNamespace, "application-identity-secrets", productconfig.ApplicationCoreNamespace, "auth-service-secrets")
		} else {
			authSecret, authErr = helm.EnsureApplicationIdentitySecret(ctx, o.HelmRun, opts.KubeconfigPath, productconfig.ApplicationCoreNamespace, "auth-service-secrets")
		}
		checks = append(checks, authSecret.Checks...)
		if authErr != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", authErr), func() []evidence.Check {
				_ = authSecret.Cleanup()
				return nil
			})
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
	}
	if resolved.ChannelIntegrationsEnabled {
		var runtimeSecret helm.PreparedRelease
		var runtimeErr error
		if strings.TrimSpace(opts.ChannelIntegrationRuntimePath) != "" {
			runtimeSecret, runtimeErr = helm.EnsureSecretFromFile(ctx, o.HelmRun, opts.KubeconfigPath,
				productconfig.ControlPlaneAppsNamespace, "channel-integration-runtime", "runtime.json", opts.ChannelIntegrationRuntimePath)
		} else {
			runtimeSecret, runtimeErr = helm.EnsureSecretPresent(ctx, o.HelmRun, opts.KubeconfigPath,
				productconfig.ControlPlaneAppsNamespace, "channel-integration-runtime", "runtime.json")
		}
		checks = append(checks, runtimeSecret.Checks...)
		if runtimeErr != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: channel-integrations runtime Secret: %w", runtimeErr), func() []evidence.Check {
				_ = runtimeSecret.Cleanup()
				_ = keysReplica.Cleanup()
				_ = importer.Rollback(ctx, preloadResult.NewlyImported)
				return rollback()
			})
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
		channelRuntimeRollback = runtimeSecret.Cleanup
	}
	if (resolved.CommerceEnabled || resolved.ApplicationIdentityEnabled || resolved.ApplicationAuthEnabled) && resolved.PostgresImageReference != "" {
		dbReplica, dbReplicaErr := helm.EnsureControlPlaneDatabaseConnectionReplica(ctx, o.HelmRun, opts.KubeconfigPath, productconfig.InfrastructureNamespace, productconfig.ControlPlaneAppsNamespace, "controlplane-database-connection")
		checks = append(checks, dbReplica.Checks...)
		if dbReplicaErr != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", dbReplicaErr), func() []evidence.Check {
				_ = dbReplica.Cleanup()
				_ = keysReplica.Cleanup()
				_ = importer.Rollback(ctx, preloadResult.NewlyImported)
				return rollback()
			})
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
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
		for _, valuesPath := range []string{registryValuesPath, dnsValuesPath, inferenceValuesPath} {
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

	appsTLSNamespace := ""
	if resolved.ChannelIntegrationsEnabled || resolved.CommerceEnabled || resolved.ApplicationIdentityEnabled || resolved.ApplicationAuthEnabled {
		appsTLSNamespace = productconfig.ControlPlaneAppsNamespace
	}
	tlsPrepared, tlsErr := helm.EnsureApplianceTLSSecrets(ctx, o.HelmRun, opts.KubeconfigPath, helm.ApplianceTLSOptions{
		ControlNamespace:  opts.ChartNamespace,
		AppsNamespace:     appsTLSNamespace,
		ArtifactNamespace: registryNamespace,
		IncludeArtifacts:  targetArtifact,
		FQDN:              identity.FQDN,
		NodeIPv4:          nodeIPv4,
		ExtraSANs:         tlsSANs,
		TLSSecretName:     opts.TLSSecretName,
		CertificatePath:   opts.TLSCertificatePath,
		KeyPath:           opts.TLSKeyPath,
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
	if resolved.InferenceEnabled {
		if err := cluster.LabelInferenceNode(ctx, o.HelmRun, opts.KubeconfigPath, opts.NodeName); err != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", err), func() []evidence.Check {
				_ = importer.Rollback(ctx, preloadResult.NewlyImported)
				return rollback()
			})
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
	}
	// Upgrade is also the migration point for receipts written before node UID
	// inventory existed. Refresh from the live API rather than carrying a node
	// name forward as durable cluster identity.
	controlPlaneNodeUID, err := cluster.NodeUID(ctx, o.HelmRun, opts.KubeconfigPath, opts.NodeName)
	if err != nil {
		rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", err), func() []evidence.Check {
			_ = importer.Rollback(ctx, preloadResult.NewlyImported)
			return rollback()
		})
		checks = append(checks, rollbackChecks...)
		return nil, checks, failErr
	}
	if resolved.InferenceEnabled && productconfig.HostNVIDIAAvailable() {
		if err := nvidia.EnsureK3sRuntime(ctx, o.HelmRun, opts.KubeconfigPath, nvidia.DefaultContainerdConfig, opts.K3sUnitName, o.K3s.Restart); err != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: configure NVIDIA runtime for K3s: %w", err), func() []evidence.Check {
				_ = importer.Rollback(ctx, preloadResult.NewlyImported)
				return rollback()
			})
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
		if err := importer.WaitReady(ctx, 60*time.Second, time.Second); err != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: containerd not ready after NVIDIA runtime configure: %w", err), func() []evidence.Check {
				_ = importer.Rollback(ctx, preloadResult.NewlyImported)
				return rollback()
			})
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
		checks = append(checks, evidence.Check{
			ID: "nvidia-k3s-runtime", Category: "inference", Status: evidence.StatusPass,
			Message:   "configured NVIDIA container runtime for K3s and applied RuntimeClass nvidia",
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
	}
	traefikLBCheck, traefikLBErr := helm.EnsureTraefikManagementExternalIPs(ctx, o.HelmRun, opts.KubeconfigPath, hostdns.LiteralIPv4s(opts.TLSSANs...)...)
	checks = append(checks, traefikLBCheck)
	if traefikLBErr != nil {
		rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", traefikLBErr), func() []evidence.Check {
			_ = importer.Rollback(ctx, preloadResult.NewlyImported)
			return rollback()
		})
		checks = append(checks, rollbackChecks...)
		return nil, checks, failErr
	}
	traefikTimeoutCheck, traefikTimeoutErr := helm.EnsureTraefikTransferTimeouts(ctx, o.HelmRun, opts.KubeconfigPath, productconfig.HasCapabilityInCatalog(effectiveProfile, productconfig.CapabilityPlaintextHTTP, resolved.ProfileCatalog), opts.NodeName)
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
	for _, dir := range hostdirs.ServiceLogDirs(targetArtifact, targetFiles, targetDNS, targetInference, resolved.HostEnabled) {
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
	for _, file := range hostdirs.ServiceLogFiles(targetArtifact, targetFiles, targetDNS, targetInference, resolved.HostEnabled) {
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
	{
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
		if targetLANDiscovery {
			enableMDNS := o.EnsureMDNSEnabled
			if enableMDNS == nil {
				enableMDNS = hostagent.EnsureMDNSEnabled
			}
			if err := enableMDNS(ctx, opts.HostAgentSocketPath, identity.Name); err != nil {
				rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: enable lan-discovery mDNS: %w", err), rollback)
				checks = append(checks, rollbackChecks...)
				return nil, checks, failErr
			}
			checks = append(checks, evidence.Check{
				ID: "host-mdns-enabled", Category: "host", Status: evidence.StatusPass,
				Message:   "lan-discovery mDNS enabled for appliance discovery",
				Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
			})
		} else {
			disableMDNS := o.EnsureMDNSDisabled
			if disableMDNS == nil {
				disableMDNS = hostagent.EnsureMDNSDisabled
			}
			if err := disableMDNS(ctx, opts.HostAgentSocketPath); err != nil {
				rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: disable lan-discovery mDNS: %w", err), rollback)
				checks = append(checks, rollbackChecks...)
				return nil, checks, failErr
			}
			checks = append(checks, evidence.Check{
				ID: "host-mdns-disabled", Category: "host", Status: evidence.StatusPass,
				Message:   "lan-discovery capability is not enabled; host mDNS disabled",
				Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
			})
		}
		// Wi-Fi AP apply is deferred until after appliance-dns (when the landns
		// capability is on the profile) so CoreDNS owns host :53 first and the
		// AP bind-probe falls back to DHCP-only DNS mode for manage.ap.
	}
	if strings.TrimSpace(opts.CloudflaredTunnelTokenPath) != "" {
		if !resolved.ChannelIntegrationsEnabled && !resolved.ApplicationIdentityEnabled && !resolved.ApplicationAuthEnabled {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: Cloudflare Tunnel connector requires an application-facing capability"), rollback)
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
		if strings.TrimSpace(resolved.CloudflaredBinaryPath) == "" {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: local Cloudflare Tunnel requested but the signed bundle has no cloudflared binary"), rollback)
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
		installCloudflared := o.InstallCloudflared
		if installCloudflared == nil {
			installCloudflared = func(cloudflared.InstallSpec) (func() error, error) { return func() error { return nil }, nil }
		}
		cloudflaredRollback, err = installCloudflared(cloudflared.InstallSpec{
			SourceBinaryPath: resolved.CloudflaredBinaryPath,
			BinaryDestPath:   opts.CloudflaredBinaryDestPath,
			UnitPath:         opts.CloudflaredUnitPath,
			UnitName:         opts.CloudflaredUnitName,
			TokenSourcePath:  opts.CloudflaredTunnelTokenPath,
			TokenDestPath:    opts.CloudflaredTokenDestPath,
		})
		if err != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: install Cloudflare Tunnel connector: %w", err), rollback)
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
		checks = append(checks, evidence.Check{ID: "cloudflared-installed", Category: "host", Status: evidence.StatusPass, Message: "local Cloudflare Tunnel connector installed with a release-owned localhost origin redirect to the K3s Traefik ServiceLB; tunnel token remains redacted", Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true})
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
		if err := hostpackages.QuiesceConflictingHostDaemons(); err != nil {
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
	if resolved.ApplicationAuthEnabled {
		ready, waitErr := helm.WaitDeploymentAvailable(ctx, o.HelmRun, opts.KubeconfigPath, productconfig.ApplicationCoreNamespace, "auth-service", "application-auth-ready")
		checks = append(checks, ready)
		if waitErr != nil {
			appCoreDiag := helm.ChartRelease{Name: opts.ChartReleaseName, ChartPath: chartPath, Namespace: opts.ChartNamespace, ValuesPath: preparedValuesPath}
			checks = append(checks, helm.CollectFailureDiagnostics(ctx, o.HelmRun, opts.KubeconfigPath, appCoreDiag)...)
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: wait for auth-service: %w", waitErr), rollback)
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
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
	cluster := installed.Cluster
	if cluster == nil || cluster.ID == "" {
		// Receipts created before cluster identity was made explicit describe
		// the same single-server topology. Upgrade is the safe migration point
		// because it already owns the authoritative state rewrite.
		migrated := state.NewSingleServerCluster(installed.ApplianceInstanceID, opts.NodeName, k3s.DefaultClusterCIDR, k3s.DefaultServiceCIDR)
		cluster = &migrated
	}
	// Copy before changing the state prepared from the prior receipt. This
	// keeps a failed transaction's in-memory source receipt immutable.
	clusterCopy := *cluster
	clusterCopy.Nodes = append([]state.ClusterNode(nil), cluster.Nodes...)
	controlPlaneFound := false
	for i := range clusterCopy.Nodes {
		if clusterCopy.Nodes[i].Name == opts.NodeName && clusterCopy.Nodes[i].Role == state.NodeRoleControlPlane {
			clusterCopy.Nodes[i].NodeUID = controlPlaneNodeUID
			controlPlaneFound = true
			break
		}
	}
	if !controlPlaneFound {
		return nil, checks, fmt.Errorf("upgrade: cluster inventory has no control-plane node %q", opts.NodeName)
	}
	cluster = &clusterCopy
	updated := &state.InstalledState{
		SchemaVersion:       1,
		ApplianceInstanceID: installed.ApplianceInstanceID,
		InstalledVersion:    targetVersion,
		InstalledReleaseID:  resolved.ReleaseID,
		ApplianceProfile:    effectiveProfile,
		ApplianceName:       identity.Name,
		DNSZone:             identity.Zone,
		Cluster:             cluster,
		Runtimes:            resolved.Runtimes,
		Components: state.Components{
			K3sVersion:            resolved.Compatibility.K3sVersion,
			ChartVersion:          resolved.Compatibility.ChartVersion,
			DatabaseEngine:        install.DatabaseEngine(resolved),
			ArtifactServerVersion: resolved.ArtifactServerComponentVersion(resolved.Compatibility.ArtifactServerVersion),
			DNSVersion:            resolved.DNSComponentVersion(resolved.Compatibility.DNSVersion),
			InferenceVersion:      resolved.InferenceComponentVersion(resolved.Compatibility.InferenceVersion),
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
