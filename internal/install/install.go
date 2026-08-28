package install

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/helm"
	"github.com/zoncaesaradmin/appliance-ctl/internal/host"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostagent"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdirs"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdns"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostpackages"
	"github.com/zoncaesaradmin/appliance-ctl/internal/images"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/metadatabundle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/preflight"
	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
	"github.com/zoncaesaradmin/appliance-ctl/internal/rolloutsets"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
	"github.com/zoncaesaradmin/appliance-ctl/internal/zonctlhost"
)

// containerdReadyTimeout/containerdReadyPollInterval bound how long
// Install waits for K3s's embedded containerd to accept connections
// after (re)starting the service, before giving up. K3s startup is
// normally a few seconds; this leaves generous headroom for a loaded or
// slow-disk host without hanging indefinitely on a truly dead service.
const (
	containerdReadyTimeout      = 60 * time.Second
	containerdReadyPollInterval = 1 * time.Second
	workflowsReleaseName        = "appliance-workflows"
	workflowsNamespace          = productconfig.WorkflowsControllerNamespace
	workflowsBuildNamespace     = productconfig.WorkflowsBuildNamespace
	registryReleaseName         = "appliance-registry"
	messageBrokerReleaseName    = "appliance-message-broker"
	messageBrokerNamespace      = "ace-system"
	registryNamespace           = "artifacts"
	dnsReleaseName              = "appliance-dns"
	dnsNamespace                = "dns"
	inferenceReleaseName        = "appliance-inference"
	inferenceNamespace          = "inference"
)

type freshReleaseResult struct {
	checks   []evidence.Check
	rollback func() error
	err      error
}

// Options fully parameterizes a fresh install. Every path is explicit
// (no hidden defaults inside this package) so tests can point every
// mutating operation at a temp directory; cmd/zonctl is responsible for
// filling in the real system paths. Artifact resolution is the caller's
// Source, not part of Options.
type Options struct {
	ApplianceVersion string

	InstalledStatePath      string
	K3sConfigPath           string
	K3sUnitPath             string
	K3sBinaryDestPath       string
	K3sUnitName             string
	HostAgentBinaryDestPath string
	HostAgentUnitPath       string
	HostAgentUnitName       string
	HostAgentSocketPath     string
	HostAgentLogPath        string
	// KubectlSymlinkPath is where a "kubectl" symlink to K3sBinaryDestPath
	// is created (K3s is a multicall binary, so this makes plain
	// `kubectl` work as a real, standalone command on the host).
	KubectlSymlinkPath string
	K3sCNINetworkDir   string
	K3sCNIInterfaces   []string
	// K3sDataDir is K3s's own data directory (e.g. /var/lib/rancher/k3s),
	// distinct from K3sConfigPath. It backs the "data-dir" config key,
	// the preflight disk-space check, and is what `zonctl backup`
	// snapshots.
	K3sDataDir       string
	KubeconfigPath   string
	ApplianceProfile string
	// WorkspaceRootDir is the host directory backing the workspace
	// storage hostPath PersistentVolume (builder profile only). Prepared
	// with the correct owner before the chart is applied; see
	// internal/hostdirs.
	WorkspaceRootDir string
	// MetadataBundlesDir is the host directory for extracted metadata bundles
	// mounted into the control plane. Empty defaults to
	// hostdirs.MetadataBundlesDir.
	MetadataBundlesDir string
	NodeName           string
	ApplianceName      string
	DNSZone            string
	// Host packages from the super-set bundle are always staged when present so
	// day-2 host APIs can enable mDNS / client Wi-Fi / Wi-Fi AP. Services are not enabled here.
	TLSSANs                []string
	ZonctlRealDestPath     string
	ZonctlLauncherDestPath string
	ChartReleaseName       string
	ChartNamespace         string

	// K3sRegistriesPath is where optional image-pull registries.yaml is
	// written (default /etc/rancher/k3s/registries.yaml). Empty disables
	// writing even when ImagePullRegistry is set.
	K3sRegistriesPath string
	// ImagePullRegistry, when Registry is non-empty, configures K3s
	// containerd to pull from that private registry (auth + TLS). Offline
	// bundle preload remains the primary image source; this only enables
	// additional pulls (for example lab control-plane image updates).
	ImagePullRegistry k3s.RegistriesConfig

	// TransactionID is the lifecycle journal transaction this install
	// belongs to, recorded into the persisted installed-state.
	TransactionID string

	// PriorInstallAttempted should be true only when the transaction
	// journal shows an interrupted in-progress install on this host. It
	// disambiguates a leftover K3s service from a crashed install versus a
	// truly unrelated cluster; see
	// internal/k3s.DecideOwnership.
	PriorInstallAttempted bool

	// ForceAdopt overrides the safety gate on an existing, unrecorded K3s
	// cluster that isn't obviously safe to adopt (unhealthy and/or
	// carrying foreign workloads). See internal/k3s.DecideOwnership.
	ForceAdopt bool

	// PreserveFailedState disables install rollback on failure so the
	// partially installed host can be inspected in place for debugging.
	// The default remains fail-closed rollback for normal operator use.
	PreserveFailedState bool
}

// Orchestrator holds the injectable adapters Install drives. Tests
// construct one with fakes; production code uses NewOrchestrator.
type Orchestrator struct {
	K3s        k3s.Ops
	ImagesRun  cli.Runner
	HelmRun    cli.Runner
	ClusterRun cli.Runner // kubectl calls used to inspect an existing cluster before adopting it
	DetectHost func(host.Options) (host.Facts, error)
	// EnsureOwnedDir prepares a host directory backing a static hostPath
	// PersistentVolume (currently just workspace storage) with the
	// correct owner before the chart mounts it — see internal/hostdirs
	// for why this can't just be left to Kubernetes' own fsGroup
	// handling.
	EnsureOwnedDir func(path string, uid, gid int, perm os.FileMode) error
	// EnsureOwnedFile reseeds operator-facing log files (for example artifact server
	// application.log) to a host-readable mode after upstream may have
	// created them as 0600.
	EnsureOwnedFile func(path string, uid, gid int, perm os.FileMode) error
	// PrepareHostDNS frees hostNetwork :53 (disables systemd-resolved stub)
	// and seeds /etc/hosts for the node name so preflight still passes after
	// the stub (and MagicDNS) is gone. Tests leave this nil as a no-op.
	PrepareHostDNS func(hostdns.PrepareConfig) (hostdns.PrepareResult, error)
	// RestoreHostDNS undoes PrepareHostDNS on rollback/uninstall.
	RestoreHostDNS      func() error
	InstallHostAgent    func(hostagent.InstallSpec) (func() error, error)
	InstallHostPackages func(hostpackages.InstallSpec) (func() error, error)
	// EnsureDay2FeaturesDisabled resets client Wi-Fi/Wi-Fi AP (and clears any
	// stale mDNS state) after host-agent install. Nil uses
	// hostagent.EnsureDay2FeaturesDisabled.
	EnsureDay2FeaturesDisabled func(context.Context, string) error
	// EnsureMDNSEnabled enables the appliance's default local discovery service
	// after the host agent is ready. Wi-Fi modes remain disabled.
	EnsureMDNSEnabled func(context.Context, string) error
}

// NewOrchestrator wires an Orchestrator to the real K3s, ctr, helm/kubectl,
// and host-detection adapters.
func NewOrchestrator() *Orchestrator {
	return &Orchestrator{
		K3s: k3s.DefaultOps(), ImagesRun: cli.Exec, HelmRun: cli.Exec, ClusterRun: cli.Exec, DetectHost: host.Detect,
		EnsureOwnedDir: func(path string, uid, gid int, perm os.FileMode) error {
			return hostdirs.EnsureOwnedDir(path, uid, gid, perm, os.Chown)
		},
		EnsureOwnedFile: func(path string, uid, gid int, perm os.FileMode) error {
			return hostdirs.EnsureOwnedFile(path, uid, gid, perm, os.Chown)
		},
		PrepareHostDNS:      hostdns.Prepare,
		RestoreHostDNS:      hostdns.Restore,
		InstallHostAgent:    hostagent.InstallOrUpdate,
		InstallHostPackages: hostpackages.InstallRequiredPackages,
	}
}

// Install runs the fresh-install sequence end to end against a verified
// release source. It returns the full evidence check set gathered along
// the way even on failure, and leaves no more installed than there was
// before it started: every mutating step past K3s startup registers a
// rollback that runs, in reverse order, on any later failure.
func (o *Orchestrator) Install(ctx context.Context, source Source, opts Options) (*state.InstalledState, []evidence.Check, error) {
	var checks []evidence.Check
	var rollbacks []func() error
	runRollbacks := func() error {
		var errs []error
		for i := len(rollbacks) - 1; i >= 0; i-- {
			if err := rollbacks[i](); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	runExtraRollbacks := func(extra []func() error) error {
		var errs []error
		for i := len(extra) - 1; i >= 0; i-- {
			if err := extra[i](); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	cleanupOnFailure := func(extra ...func() error) error {
		if opts.PreserveFailedState {
			return nil
		}
		return errors.Join(runExtraRollbacks(extra), runRollbacks())
	}
	failInstall := func(primary error, cleanup error) error {
		if opts.PreserveFailedState {
			if cleanup != nil {
				return errors.Join(primary, fmt.Errorf("install cleanup skipped because --preserve-failed-state was set"))
			}
			return fmt.Errorf("%w (failed state preserved due to --preserve-failed-state)", primary)
		}
		return joinCleanupError(primary, cleanup)
	}

	resolved, resolveChecks, err := source.Resolve(ctx, opts.ApplianceProfile)
	checks = append(checks, resolveChecks...)
	if err != nil {
		return nil, checks, err
	}
	effectiveProfile := resolved.EffectiveProfile
	targetVersion := strings.TrimSpace(resolved.BundleVersion)
	if targetVersion == "" {
		targetVersion = strings.TrimSpace(opts.ApplianceVersion)
	}
	if targetVersion == "" {
		return nil, checks, fmt.Errorf("install: resolved bundle version is empty")
	}
	identity, err := productconfig.ResolveApplianceIdentity(opts.ApplianceName, opts.DNSZone)
	if err != nil {
		return nil, checks, fmt.Errorf("install: %w", err)
	}
	nodeIPv4 := preferredLocalIPv4(opts.TLSSANs...)
	preparedValuesPath, cleanupPreparedValues, err := productconfig.PrepareValuesFile(resolved.ConfigurationPath, effectiveProfile, resolved.ProfileCatalog, resolved.WorkspaceProvisionerImageReference, resolved.BuilderImageReference, resolved.HostAgentImageReference, identity.Name, identity.Zone, nodeIPv4, resolved.ArtifactServerImageReference, resolved.BlobStorageImageReference)
	if err != nil {
		return nil, checks, fmt.Errorf("install: %w", err)
	}
	defer cleanupPreparedValues()
	registryValuesPath := ""
	cleanupRegistryValues := func() {}
	if resolved.ArtifactEnabled {
		registryValuesPath, cleanupRegistryValues, err = productconfig.PrepareRegistryValuesFile(filepath.Dir(resolved.ConfigurationPath), resolved.ArtifactServerImageReference, identity.FQDN)
		if err != nil {
			return nil, checks, fmt.Errorf("install: %w", err)
		}
		defer cleanupRegistryValues()
	}
	dnsValuesPath := ""
	cleanupDNSValues := func() {}
	if resolved.DNSEnabled {
		dnsValuesPath, cleanupDNSValues, err = productconfig.PrepareDNSValuesFile(filepath.Dir(resolved.ConfigurationPath), resolved.DNSImageReference, identity.Zone, nodeIPv4)
		if err != nil {
			return nil, checks, fmt.Errorf("install: %w", err)
		}
		defer cleanupDNSValues()
	}
	inferenceValuesPath := ""
	cleanupInferenceValues := func() {}
	if resolved.InferenceEnabled {
		inferenceValuesPath, cleanupInferenceValues, err = productconfig.PrepareInferenceValuesFile(filepath.Dir(resolved.ConfigurationPath), resolved.InferenceImageReference)
		if err != nil {
			return nil, checks, fmt.Errorf("install: %w", err)
		}
		defer cleanupInferenceValues()
	}

	// Gated on the Build capability, not the "builder" profile name
	// directly: more than one profile can enable Build, and this
	// directory only needs to exist when Build does. The workspace
	// storage PV is a static hostPath, and Kubernetes' fsGroup ownership
	// recursion is not reliably applied to hostPath volumes (unlike the
	// main data PV, which K3s's own local-path-provisioner provisions
	// and permissions correctly). Seed the right owner ourselves, before
	// Helm ever applies the chart, rather than discover the gap as a
	// Permission denied inside a workflow pod.
	if resolved.BuildEnabled && opts.WorkspaceRootDir != "" {
		if err := o.EnsureOwnedDir(opts.WorkspaceRootDir, hostdirs.ApplianceDirOwnerUID, hostdirs.ApplianceSharedFSGID, hostdirs.WorkspaceDirMode); err != nil {
			return nil, checks, fmt.Errorf("install: prepare workspace directory: %w", err)
		}
		checks = append(checks, evidence.Check{
			ID: "workspace-directory-owned", Category: "host", Status: evidence.StatusPass,
			Message:   fmt.Sprintf("%s owned by %d:%d", opts.WorkspaceRootDir, hostdirs.ApplianceDirOwnerUID, hostdirs.ApplianceSharedFSGID),
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
	}
	if resolved.InferenceEnabled {
		if err := o.EnsureOwnedDir(hostdirs.InferenceModelsDir, hostdirs.InferenceDirOwnerUID, hostdirs.ApplianceSharedFSGID, hostdirs.WorkspaceDirMode); err != nil {
			return nil, checks, fmt.Errorf("install: prepare inference models directory: %w", err)
		}
		checks = append(checks, evidence.Check{
			ID: "inference-models-directory-owned", Category: "host", Status: evidence.StatusPass,
			Message:   fmt.Sprintf("%s owned by %d:%d", hostdirs.InferenceModelsDir, hostdirs.InferenceDirOwnerUID, hostdirs.ApplianceSharedFSGID),
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
	}
	if err := o.EnsureOwnedDir(hostdirs.BlobStorageDir, hostdirs.BlobStorageDirOwnerUID, hostdirs.ApplianceSharedFSGID, hostdirs.WorkspaceDirMode); err != nil {
		return nil, checks, fmt.Errorf("install: prepare blob storage directory: %w", err)
	}
	checks = append(checks, evidence.Check{
		ID: "blob-storage-directory-owned", Category: "host", Status: evidence.StatusPass,
		Message:   fmt.Sprintf("%s owned by %d:%d", hostdirs.BlobStorageDir, hostdirs.BlobStorageDirOwnerUID, hostdirs.ApplianceSharedFSGID),
		Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	})

	// Host-visible metadata-bundle tree: extract before Helm so Automation
	// Runtime mounts a real initial active policy (not only the embedded
	// fallback) and so the selected appliance profile is validated against
	// the policy catalog fail-closed.
	metadataBundlesDir := strings.TrimSpace(opts.MetadataBundlesDir)
	if metadataBundlesDir == "" {
		metadataBundlesDir = hostdirs.MetadataBundlesDir
	}
	if err := o.EnsureOwnedDir(metadataBundlesDir, hostdirs.AutomationRuntimeDirOwnerUID, hostdirs.ApplianceSharedFSGID, hostdirs.SharedWritableDirMode); err != nil {
		return nil, checks, fmt.Errorf("install: prepare metadata-bundles directory: %w", err)
	}
	checks = append(checks, evidence.Check{
		ID: "metadata-bundles-directory-owned", Category: "host", Status: evidence.StatusPass,
		Message:   fmt.Sprintf("%s owned by %d:%d", metadataBundlesDir, hostdirs.AutomationRuntimeDirOwnerUID, hostdirs.ApplianceSharedFSGID),
		Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	})
	metadataVersion, metadataDigest, err := stageMetadataBundle(
		resolved.MetadataBundleArchivePath,
		filepath.Join(filepath.Dir(opts.InstalledStatePath), "metadata-bundles"),
		metadataBundlesDir,
		effectiveProfile,
	)
	if err != nil {
		return nil, checks, fmt.Errorf("install: stage metadata bundle: %w", err)
	}
	checks = append(checks, evidence.Check{
		ID: "metadata-bundle-staged", Category: "manifest", Status: evidence.StatusPass,
		Message:   fmt.Sprintf("staged and extracted metadata bundle %s (profile %s validated)", metadataVersion, effectiveProfile),
		Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	})

	signal, err := o.K3s.DetectService(opts.K3sUnitName)
	if err != nil {
		return nil, checks, fmt.Errorf("install: detect k3s service: %w", err)
	}

	// Ownership gate before host DNS prep and other host mutations: a live
	// owned appliance holds product CoreDNS on :53. Refuse reuse/upgrade so
	// callers uninstall first and reinstall cleanly (in-place public upgrade
	// is not the supported reinstall path for now).
	existing, err := state.Load(opts.InstalledStatePath)
	if err != nil {
		return nil, checks, fmt.Errorf("install: %w", err)
	}
	if existing != nil && existing.K3sOwnership.Owned && !signal.Detected && k3sArtifactsAbsent(opts.K3sUnitPath, opts.K3sBinaryDestPath, opts.K3sConfigPath) {
		if err := os.Remove(opts.InstalledStatePath); err != nil && !os.IsNotExist(err) {
			return nil, checks, fmt.Errorf("install: remove stale installed-state: %w", err)
		}
		checks = append(checks, evidence.Check{
			ID: "k3s-stale-ownership-cleared", Category: "k3s", Status: evidence.StatusPass,
			Message:   "installed-state recorded owned K3s, but the K3s service, unit, binary, and config are absent; stale ownership record removed before fresh install",
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
		existing = nil
	}
	if existing == nil && signal.Detected && signal.Active {
		healthy, foreignNamespaces, inspectErr := k3s.InspectCluster(ctx, o.ClusterRun, opts.KubeconfigPath, opts.ChartNamespace)
		if inspectErr != nil {
			return nil, checks, fmt.Errorf("install: inspect existing cluster: %w", inspectErr)
		}
		signal.Healthy = healthy
		signal.ForeignNamespaces = foreignNamespaces
		if runningVersion, versionErr := o.K3s.Version(opts.K3sBinaryDestPath); versionErr == nil {
			signal.RunningVersion = runningVersion
		}
	}
	decision, reason := k3s.DecideOwnership(targetVersion, existing, signal, opts.PriorInstallAttempted, opts.ForceAdopt)
	if decision != k3s.DecisionFreshInstall && decision != k3s.DecisionAdoptExisting {
		return nil, checks, fmt.Errorf("install: refusing to install (%s): %s", decision, reason)
	}
	checks = append(checks, evidence.Check{
		ID: "k3s-ownership-decision", Category: "k3s", Status: evidence.StatusPass,
		Message: fmt.Sprintf("%s: %s", decision, reason), Timestamp: time.Now().UTC(),
		Idempotent: true, SecretsRedacted: true,
	})

	requiredPorts := append([]int{}, preflight.RequiredPorts...)
	if resolved.DNSEnabled {
		// Ubuntu's systemd-resolved stub owns 127.0.0.53:53 and blocks any
		// wildcard bind on :53. Free that before preflight so the port-53
		// check reflects the post-prep host, and so CoreDNS can start.
		// Also seed /etc/hosts: after the stub is gone, short names that only
		// resolved via MagicDNS/stub would fail internal-dns-resolvable.
		// NewOrchestrator wires PrepareHostDNS; tests leave it nil as a no-op.
		if o.PrepareHostDNS != nil {
			prep, prepErr := o.PrepareHostDNS(hostDNSPrepareConfig(opts))
			if prepErr != nil {
				return nil, checks, fmt.Errorf("install: prepare host for LAN DNS on port 53: %w", prepErr)
			}
			if prep.Changed {
				if o.RestoreHostDNS != nil {
					rollbacks = append(rollbacks, o.RestoreHostDNS)
				}
				msg := "prepared host for LAN DNS (systemd-resolved stub disabled and/or node hostname seeded in /etc/hosts)"
				checks = append(checks, evidence.Check{
					ID: "host-dns-stub-disabled", Category: "host", Status: evidence.StatusPass,
					Message:   msg,
					Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
				})
			}
		}
		requiredPorts = append(requiredPorts, 53)
	}
	facts, err := o.DetectHost(host.Options{DataDir: opts.K3sDataDir, RequiredPorts: requiredPorts})
	if err != nil {
		return nil, checks, failInstall(fmt.Errorf("install: detect host: %w", err), runRollbacks())
	}
	if signal.Detected && signal.Active {
		// K3s already owns the baseline API/CNI ports; clear those so
		// adopt/reinstall is not blocked. Port 53 is appliance DNS, not
		// K3s, so keep any remaining conflict visible.
		for _, port := range preflight.RequiredPorts {
			delete(facts.PortsInUse, port)
		}
	}
	preflightChecks := preflight.Run(facts)
	checks = append(checks, toEvidenceChecks(preflightChecks)...)
	if overall := preflight.OverallStatus(preflightChecks); overall == preflight.StatusOperatorAction || overall == preflight.StatusUnsupported {
		return nil, checks, failInstall(fmt.Errorf("install: preflight blocked with status %q; resolve reported findings before installing", overall), runRollbacks())
	}
	baselineCheck := CheckBundleHostBaseline(facts, resolved.HostBaseline)
	checks = append(checks, baselineCheck)
	if baselineCheck.Status != evidence.StatusPass {
		return nil, checks, failInstall(fmt.Errorf("install: target host does not match the signed bundle baseline"), runRollbacks())
	}
	if resolved.HostEnabled {
		// Stage offline host packages with the deviceuser pack so day-2 host
		// operations never need apt. Services remain disabled until enabled by API.
		if resolved.HostPackagesRootDir == "" {
			return nil, checks, failInstall(fmt.Errorf("install: host capability requires deviceuser host-packages (mdns + wifi-client + wifi-ap)"), runRollbacks())
		}
		installHostPackages := o.InstallHostPackages
		if installHostPackages == nil {
			installHostPackages = func(hostpackages.InstallSpec) (func() error, error) {
				return func() error { return nil }, nil
			}
		}
		hostPackagesRollback, err := installHostPackages(hostpackages.InstallSpec{
			RootDir: resolved.HostPackagesRootDir, OS: facts.OS, OSVersion: facts.OSVersion, Arch: facts.Arch,
		})
		if err != nil {
			return nil, checks, failInstall(fmt.Errorf("install: install host packages: %w", err), runRollbacks())
		}
		rollbacks = append(rollbacks, hostPackagesRollback)
		checks = append(checks, evidence.Check{
			ID: "host-packages-installed", Category: "host", Status: evidence.StatusPass,
			Message:   fmt.Sprintf("installed offline host packages from %s for day-2 mDNS, client Wi-Fi, and Wi-Fi AP (services remain off until enabled via API)", resolved.HostPackagesRootDir),
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
	}

	// A fresh install always installs K3s. Adopting an existing cluster
	// only touches K3s if the running version doesn't match the target's
	// pinned version; a matching version is left alone entirely, and we
	// never register a stop-on-rollback for a service we didn't start.
	needsK3sInstall := decision == k3s.DecisionFreshInstall || signal.RunningVersion != resolved.Compatibility.K3sVersion
	if needsK3sInstall {
		// KillMode=process leaves containerd-shim orphans across stop /
		// uninstall. Clear them (and stale CNI) before (re)starting so
		// the new process does not inherit a split-brain runtime that
		// breaks ClusterIP routing and PVC provisioning.
		if !signal.Active {
			if err := o.K3s.CleanupNodeNetwork(opts.K3sCNINetworkDir, opts.K3sCNIInterfaces); err != nil {
				return nil, checks, fmt.Errorf("install: clean leftover k3s runtime before start: %w", err)
			}
		}
		// Uninstall preserves /var/lib/rancher/k3s by design. A fresh
		// reinstall that pins cluster-cidr (10.44/16 so 10.42 is free for
		// WiFi AP) against leftover etcd/node PodCIDR 10.42.0.0/24 makes
		// flannel exit and containerd disappear mid image-preload. Wipe
		// the K3s data dir only for DecisionFreshInstall.
		if decision == k3s.DecisionFreshInstall {
			if err := wipeK3sDataDir(opts.K3sDataDir); err != nil {
				return nil, checks, failInstall(fmt.Errorf("install: reset k3s data dir for fresh install: %w", err), runRollbacks())
			}
			checks = append(checks, evidence.Check{
				ID: "k3s-data-dir-reset", Category: "k3s", Status: evidence.StatusPass,
				Message:   fmt.Sprintf("reset k3s data directory %s for fresh cluster network params", opts.K3sDataDir),
				Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
			})
		}
		if err := o.K3s.WriteConfig(opts.K3sConfigPath, k3s.Config{
			NodeName:    opts.NodeName,
			DataDir:     opts.K3sDataDir,
			TLSSANs:     opts.TLSSANs,
			ClusterCIDR: k3s.DefaultClusterCIDR,
			ServiceCIDR: k3s.DefaultServiceCIDR,
		}); err != nil {
			return nil, checks, fmt.Errorf("install: write k3s config: %w", err)
		}
		if err := writeImagePullRegistries(o, opts, &checks); err != nil {
			return nil, checks, err
		}
		if err := o.K3s.WriteUnit(opts.K3sUnitPath, k3s.UnitConfig{
			BinaryPath: opts.K3sBinaryDestPath,
			ConfigPath: opts.K3sConfigPath,
		}); err != nil {
			return nil, checks, fmt.Errorf("install: write k3s unit: %w", err)
		}
		if err := o.K3s.InstallBinary(resolved.K3sBinaryPath, opts.K3sBinaryDestPath); err != nil {
			return nil, checks, fmt.Errorf("install: install k3s binary: %w", err)
		}
		if err := o.K3s.EnsureKubectlSymlink(opts.K3sBinaryDestPath, opts.KubectlSymlinkPath); err != nil {
			return nil, checks, fmt.Errorf("install: create kubectl symlink: %w", err)
		}

		if err := o.K3s.EnableAndStart(opts.K3sUnitName); err != nil {
			return nil, checks, fmt.Errorf("install: start k3s: %w", err)
		}
		// A later failure must revert the host all the way back to "no
		// K3s detected," not just stopped: DetectService's presence
		// check reads systemd's unit-file cache, which stays populated
		// (and DecideOwnership keeps rejecting future install attempts
		// with requires-force-adopt) unless the unit file is actually
		// removed and the cache refreshed, exactly like teardown does.
		rollbacks = append(rollbacks, func() error {
			var errs []error
			if err := o.K3s.Stop(opts.K3sUnitName); err != nil {
				errs = append(errs, err)
			}
			if err := o.K3s.CleanupNodeNetwork(opts.K3sCNINetworkDir, opts.K3sCNIInterfaces); err != nil {
				errs = append(errs, err)
			}
			if err := o.K3s.RemoveKubectlSymlink(opts.K3sBinaryDestPath, opts.KubectlSymlinkPath); err != nil {
				errs = append(errs, err)
			}
			removePaths := []string{opts.K3sUnitPath, opts.K3sBinaryDestPath, opts.K3sConfigPath}
			if p := strings.TrimSpace(opts.K3sRegistriesPath); p != "" {
				removePaths = append(removePaths, p)
			}
			for _, path := range removePaths {
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					errs = append(errs, err)
				}
			}
			if err := o.K3s.DaemonReload(); err != nil {
				errs = append(errs, err)
			}
			return errors.Join(errs...)
		})
	} else if err := writeImagePullRegistries(o, opts, &checks); err != nil {
		return nil, checks, err
	} else if strings.TrimSpace(opts.ImagePullRegistry.Registry) != "" {
		// registries.yaml is read at K3s start; restart so an adopted
		// cluster picks up a newly written pull-registry config.
		if err := o.K3s.Restart(opts.K3sUnitName); err != nil {
			return nil, checks, fmt.Errorf("install: restart k3s after registries.yaml: %w", err)
		}
		checks = append(checks, evidence.Check{
			ID: "k3s-registries-restart", Category: "k3s", Status: evidence.StatusPass,
			Message: "k3s restarted to load image-pull registries.yaml", Timestamp: time.Now().UTC(),
			Idempotent: true, SecretsRedacted: true,
		})
	}

	importer := &images.Importer{Run: o.ImagesRun, Namespace: "k8s.io"}

	// systemd reports the unit "started" as soon as the process launches,
	// well before K3s's embedded containerd actually accepts connections
	// on its socket; without this wait, PreloadAll below can hit a raw
	// "connection refused" on a freshly (re)started K3s.
	if err := importer.WaitReady(ctx, containerdReadyTimeout, containerdReadyPollInterval); err != nil {
		return nil, checks, failInstall(fmt.Errorf("install: %w", err), runRollbacks())
	}

	imgs := append(append([]images.Image{}, resolved.K3sImages...), resolved.FilterOCIImages(resolved.OCIImages)...)
	preloadResult, err := importer.PreloadAll(ctx, imgs)
	checks = append(checks, preloadResult.Checks...)
	if err != nil {
		return nil, checks, failInstall(fmt.Errorf("install: %w", err), runRollbacks())
	}
	rollbacks = append(rollbacks, func() error { return importer.Rollback(ctx, preloadResult.NewlyImported) })

	readinessChecks, err := helm.EnsureClusterBaseline(ctx, o.HelmRun, opts.KubeconfigPath, preparedValuesPath)
	checks = append(checks, readinessChecks...)
	if err != nil {
		return nil, checks, failInstall(fmt.Errorf("install: %w", err), runRollbacks())
	}
	// Publish https://10.42.0.1/ as a Traefik externalIP so WiFi AP clients
	// reach the UI; ServiceLB alone only binds the ethernet node VIP.
	traefikLBCheck, traefikLBErr := helm.EnsureTraefikManagementExternalIPs(ctx, o.HelmRun, opts.KubeconfigPath)
	checks = append(checks, traefikLBCheck)
	if traefikLBErr != nil {
		return nil, checks, failInstall(fmt.Errorf("install: %w", traefikLBErr), runRollbacks())
	}
	traefikTimeoutCheck, traefikTimeoutErr := helm.EnsureTraefikTransferTimeouts(ctx, o.HelmRun, opts.KubeconfigPath)
	checks = append(checks, traefikTimeoutCheck)
	if traefikTimeoutErr != nil {
		return nil, checks, failInstall(fmt.Errorf("install: %w", traefikTimeoutErr), runRollbacks())
	}
	applier := &helm.Applier{Run: o.HelmRun, Kubeconfig: opts.KubeconfigPath}

	// Private LAN registry credentials are namespaced. Mirror dockerconfig into
	// every product namespace (controlplane, apps, applications, artifacts, dns,
	// inference, workflows — never kube-system) and wire chart imagePullSecrets.
	if strings.TrimSpace(opts.ImagePullRegistry.Registry) != "" {
		if err := productconfig.InjectImagePullSecrets(preparedValuesPath, productconfig.ImagePullSecretName); err != nil {
			return nil, checks, failInstall(fmt.Errorf("install: inject image-pull secrets into values: %w", err), runRollbacks())
		}
		for _, valuesPath := range []string{registryValuesPath, dnsValuesPath, inferenceValuesPath} {
			if strings.TrimSpace(valuesPath) == "" {
				continue
			}
			if err := productconfig.InjectImagePullSecrets(valuesPath, productconfig.ImagePullSecretName); err != nil {
				return nil, checks, failInstall(fmt.Errorf("install: inject image-pull secrets into %s: %w", valuesPath, err), runRollbacks())
			}
		}
		imagePullSecrets, imagePullErr := helm.EnsureImagePullSecrets(ctx, o.HelmRun, opts.KubeconfigPath, opts.ImagePullRegistry,
			productconfig.ProductNamespaces(opts.ChartNamespace)...)
		checks = append(checks, imagePullSecrets.Checks...)
		if imagePullErr != nil {
			return nil, checks, failInstall(fmt.Errorf("install: %w", imagePullErr), runRollbacks())
		}
		rollbacks = append(rollbacks, imagePullSecrets.Cleanup)
	}

	aceSystemValuesPath, cleanupAceSystemValues, err := productconfig.PrepareValuesOverlayFile(preparedValuesPath, rolloutsets.AceSystemOverlay())
	if err != nil {
		return nil, checks, failInstall(fmt.Errorf("install: prepare ace-system values: %w", err), runRollbacks())
	}
	defer cleanupAceSystemValues()
	aceAppsValuesPath, cleanupAceAppsValues, err := productconfig.PrepareValuesOverlayFile(preparedValuesPath, rolloutsets.AceAppsOverlay())
	if err != nil {
		return nil, checks, failInstall(fmt.Errorf("install: prepare ace-apps values: %w", err), runRollbacks())
	}
	defer cleanupAceAppsValues()
	applicationSupportValuesPath, cleanupApplicationSupportValues, err := productconfig.PrepareValuesOverlayFile(preparedValuesPath, rolloutsets.ApplicationSupportOverlay())
	if err != nil {
		return nil, checks, failInstall(fmt.Errorf("install: prepare application-support values: %w", err), runRollbacks())
	}
	defer cleanupApplicationSupportValues()

	dnsSupportValuesPath := ""
	cleanupDNSSupportValues := func() {}
	if resolved.DNSEnabled {
		var prepErr error
		dnsSupportValuesPath, cleanupDNSSupportValues, prepErr = productconfig.PrepareValuesOverlayFile(preparedValuesPath, rolloutsets.DNSSupportOverlay())
		if prepErr != nil {
			return nil, checks, failInstall(fmt.Errorf("install: prepare dns-support values: %w", prepErr), runRollbacks())
		}
		defer cleanupDNSSupportValues()
	}

	workflowsSupportValuesPath := ""
	cleanupWorkflowsSupportValues := func() {}
	if resolved.WorkflowsEnabled {
		var prepErr error
		workflowsSupportValuesPath, cleanupWorkflowsSupportValues, prepErr = productconfig.PrepareValuesOverlayFile(preparedValuesPath, rolloutsets.WorkflowsSupportOverlay())
		if prepErr != nil {
			return nil, checks, failInstall(fmt.Errorf("install: prepare workflows-support values: %w", prepErr), runRollbacks())
		}
		defer cleanupWorkflowsSupportValues()
	}

	for _, dir := range hostdirs.ServiceLogDirs(
		resolved.ArtifactEnabled,
		resolved.FilesEnabled,
		resolved.WorkflowsEnabled,
		resolved.DNSEnabled,
		resolved.InferenceEnabled,
		resolved.HostEnabled,
	) {
		if err := o.EnsureOwnedDir(dir.Path, dir.UID, dir.GID, dir.Mode); err != nil {
			return nil, checks, fmt.Errorf("install: prepare service log directory %s: %w", dir.Path, err)
		}
		checks = append(checks, evidence.Check{
			ID: dir.CheckID, Category: "host", Status: evidence.StatusPass,
			Message:   fmt.Sprintf("%s owned by %d:%d", dir.Path, dir.UID, dir.GID),
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
	}
	for _, file := range hostdirs.ServiceLogFiles(
		resolved.ArtifactEnabled,
		resolved.FilesEnabled,
		resolved.WorkflowsEnabled,
		resolved.DNSEnabled,
		resolved.InferenceEnabled,
		resolved.HostEnabled,
	) {
		if o.EnsureOwnedFile == nil {
			continue
		}
		if err := o.EnsureOwnedFile(file.Path, file.UID, file.GID, file.Mode); err != nil {
			return nil, checks, fmt.Errorf("install: prepare service log file %s: %w", file.Path, err)
		}
		checks = append(checks, evidence.Check{
			ID: file.CheckID, Category: "host", Status: evidence.StatusPass,
			Message:   fmt.Sprintf("%s owned by %d:%d mode %04o", file.Path, file.UID, file.GID, file.Mode.Perm()),
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
	}
	if resolved.HostEnabled {
		installHostAgent := o.InstallHostAgent
		if installHostAgent == nil {
			installHostAgent = func(hostagent.InstallSpec) (func() error, error) {
				return func() error { return nil }, nil
			}
		}
		hostAgentRollback, err := installHostAgent(hostagent.InstallSpec{
			SourceBinaryPath: resolved.HostAgentBinaryPath,
			BinaryDestPath:   opts.HostAgentBinaryDestPath,
			UnitPath:         opts.HostAgentUnitPath,
			UnitName:         opts.HostAgentUnitName,
			SocketPath:       opts.HostAgentSocketPath,
			LogPath:          opts.HostAgentLogPath,
		})
		if err != nil {
			return nil, checks, failInstall(fmt.Errorf("install: install host agent: %w", err), runRollbacks())
		}
		rollbacks = append(rollbacks, hostAgentRollback)
		checks = append(checks, evidence.Check{
			ID: "host-agent-installed", Category: "host", Status: evidence.StatusPass,
			Message:   fmt.Sprintf("host agent installed at %s and running via %s", opts.HostAgentBinaryDestPath, opts.HostAgentUnitName),
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
		// Reset optional Wi-Fi modes and stale host state. mDNS is then enabled
		// below as the appliance's default local-discovery service.
		ensureDay2Off := o.EnsureDay2FeaturesDisabled
		if ensureDay2Off == nil {
			ensureDay2Off = hostagent.EnsureDay2FeaturesDisabled
		}
		if err := ensureDay2Off(ctx, opts.HostAgentSocketPath); err != nil {
			return nil, checks, failInstall(fmt.Errorf("install: reset day-2 host features off: %w", err), runRollbacks())
		}
		checks = append(checks, evidence.Check{
			ID: "host-wifi-features-off", Category: "host", Status: evidence.StatusPass,
			Message:   "host client Wi-Fi and Wi-Fi AP disabled (enable via Admin UI after first admin login)",
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
		enableMDNS := o.EnsureMDNSEnabled
		if enableMDNS == nil {
			enableMDNS = hostagent.EnsureMDNSEnabled
		}
		if err := enableMDNS(ctx, opts.HostAgentSocketPath); err != nil {
			return nil, checks, failInstall(fmt.Errorf("install: enable default host mdns: %w", err), runRollbacks())
		}
		checks = append(checks, evidence.Check{
			ID: "host-mdns-enabled", Category: "host", Status: evidence.StatusPass,
			Message:   "host mDNS enabled by default for appliance and reviewed application discovery",
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
	}

	clusterRun := o.ClusterRun
	if clusterRun == nil {
		clusterRun = cli.Exec
	}

	aceSystemRelease := helm.ChartRelease{
		Name:       opts.ChartReleaseName,
		ChartPath:  resolved.ChartPath,
		Namespace:  opts.ChartNamespace,
		ValuesPath: aceSystemValuesPath,
	}
	aceAppsRelease := helm.ChartRelease{
		Name:       rolloutsets.AceAppsReleaseName,
		ChartPath:  resolved.ChartPath,
		Namespace:  opts.ChartNamespace,
		ValuesPath: aceAppsValuesPath,
	}
	applicationSupportRelease := helm.ChartRelease{
		Name:       rolloutsets.ApplicationSupportReleaseName,
		ChartPath:  resolved.ChartPath,
		Namespace:  opts.ChartNamespace,
		ValuesPath: applicationSupportValuesPath,
	}
	dnsSupportRelease := helm.ChartRelease{
		Name:       rolloutsets.DNSSupportReleaseName,
		ChartPath:  resolved.ChartPath,
		Namespace:  opts.ChartNamespace,
		ValuesPath: dnsSupportValuesPath,
	}
	workflowsSupportRelease := helm.ChartRelease{
		Name:       rolloutsets.WorkflowsSupportReleaseName,
		ChartPath:  resolved.ChartPath,
		Namespace:  opts.ChartNamespace,
		ValuesPath: workflowsSupportValuesPath,
	}

	set1Releases := []helm.ChartRelease{aceSystemRelease}
	if resolved.MessageBrokerChartPath != "" {
		set1Releases = append(set1Releases, helm.ChartRelease{
			Name:      messageBrokerReleaseName,
			ChartPath: resolved.MessageBrokerChartPath,
			Namespace: messageBrokerNamespace,
		})
	}
	set1Results := make(chan freshReleaseResult, len(set1Releases))
	var set1WG sync.WaitGroup
	for _, rel := range set1Releases {
		rel := rel
		set1WG.Add(1)
		go func() {
			defer set1WG.Done()
			set1Results <- applyFreshRelease(ctx, o.HelmRun, opts.KubeconfigPath, applier, rel)
		}()
	}
	set1WG.Wait()
	close(set1Results)
	var set1Rollbacks []func() error
	var set1Err error
	for result := range set1Results {
		checks = append(checks, result.checks...)
		if result.rollback != nil {
			set1Rollbacks = append(set1Rollbacks, result.rollback)
		}
		if result.err != nil && set1Err == nil {
			set1Err = result.err
		}
	}
	if set1Err != nil {
		return nil, checks, failInstall(fmt.Errorf("install: %w", set1Err), cleanupOnFailure(set1Rollbacks...))
	}
	rollbacks = append(rollbacks, set1Rollbacks...)

	ready, waitErr := helm.WaitDeploymentAvailable(ctx, o.HelmRun, opts.KubeconfigPath, opts.ChartNamespace, "controlplane", "appliance-controlplane-ready")
	checks = append(checks, ready)
	if waitErr != nil {
		return nil, checks, failInstall(fmt.Errorf("install: wait for controlplane: %w", waitErr), cleanupOnFailure())
	}
	if resolved.MessageBrokerChartPath != "" {
		ready, waitErr = helm.WaitStatefulSetAvailable(ctx, o.HelmRun, opts.KubeconfigPath, messageBrokerNamespace, "appliance-message-broker", "appliance-message-broker-ready")
		checks = append(checks, ready)
		if waitErr != nil {
			return nil, checks, failInstall(fmt.Errorf("install: wait for message broker: %w", waitErr), cleanupOnFailure())
		}
	}

	tlsPrepared, tlsErr := helm.EnsureApplianceTLSSecrets(ctx, o.HelmRun, opts.KubeconfigPath, helm.ApplianceTLSOptions{
		ControlNamespace:  opts.ChartNamespace,
		ArtifactNamespace: registryNamespace,
		IncludeArtifacts:  resolved.ArtifactEnabled,
		FQDN:              identity.FQDN,
		NodeIPv4:          nodeIPv4,
		ExtraSANs:         opts.TLSSANs,
	})
	checks = append(checks, tlsPrepared.Checks...)
	if tlsErr != nil {
		return nil, checks, failInstall(fmt.Errorf("install: %w", tlsErr), cleanupOnFailure())
	}
	rollbacks = append(rollbacks, tlsPrepared.Cleanup)

	// ui-server / host-agent / automation-runtime live in ace-apps (chart appsNamespace).
	if err := helm.EnsureNamespace(ctx, o.HelmRun, opts.KubeconfigPath, productconfig.ControlPlaneAppsNamespace, nil); err != nil {
		return nil, checks, failInstall(fmt.Errorf("install: prepare apps namespace %s: %w", productconfig.ControlPlaneAppsNamespace, err), cleanupOnFailure())
	}

	// automation-runtime mounts secrets.keysSecretName in the apps namespace; K8s
	// Secrets are namespaced, so mirror the control-plane keys Secret only after
	// the ace-system release has created the source namespace/secret.
	keysReplica, keysReplicaErr := helm.EnsureKeysSecretReplica(ctx, o.HelmRun, opts.KubeconfigPath,
		opts.ChartNamespace, productconfig.ControlPlaneAppsNamespace, "appliance-keys")
	checks = append(checks, keysReplica.Checks...)
	if keysReplicaErr != nil {
		return nil, checks, failInstall(fmt.Errorf("install: %w", keysReplicaErr), cleanupOnFailure())
	}
	rollbacks = append(rollbacks, keysReplica.Cleanup)

	set2Result := applyFreshRelease(ctx, o.HelmRun, opts.KubeconfigPath, applier, aceAppsRelease)
	checks = append(checks, set2Result.checks...)
	if set2Result.err != nil {
		return nil, checks, failInstall(fmt.Errorf("install: %w", set2Result.err), cleanupOnFailure(set2Result.rollback))
	}
	if set2Result.rollback != nil {
		rollbacks = append(rollbacks, set2Result.rollback)
	}
	for _, wait := range []struct {
		deploy string
		id     string
	}{
		{deploy: "ui-server", id: "appliance-ui-ready"},
		{deploy: "automation-runtime", id: "appliance-automation-runtime-ready"},
	} {
		ready, waitErr = helm.WaitDeploymentAvailable(ctx, o.HelmRun, opts.KubeconfigPath, productconfig.ControlPlaneAppsNamespace, wait.deploy, wait.id)
		checks = append(checks, ready)
		if waitErr != nil {
			return nil, checks, failInstall(fmt.Errorf("install: wait for %s: %w", wait.deploy, waitErr), cleanupOnFailure())
		}
	}
	if resolved.HostEnabled {
		ready, waitErr = helm.WaitDeploymentAvailable(ctx, o.HelmRun, opts.KubeconfigPath, productconfig.ControlPlaneAppsNamespace, "host-agent", "appliance-host-agent-ready")
		checks = append(checks, ready)
		if waitErr != nil {
			return nil, checks, failInstall(fmt.Errorf("install: wait for host-agent: %w", waitErr), cleanupOnFailure())
		}
	}

	type parallelSetResult struct {
		checks    []evidence.Check
		rollbacks []func() error
		err       error
	}

	if err := helm.EnsureNamespace(ctx, o.HelmRun, opts.KubeconfigPath, productconfig.ApplicationNamespace, helm.RestrictedNamespaceLabels()); err != nil {
		return nil, checks, failInstall(fmt.Errorf("install: prepare application namespace %s: %w", productconfig.ApplicationNamespace, err), cleanupOnFailure())
	}
	if resolved.DNSEnabled {
		if err := helm.EnsureNamespace(ctx, o.HelmRun, opts.KubeconfigPath, dnsNamespace, nil); err != nil {
			return nil, checks, failInstall(fmt.Errorf("install: prepare dns namespace %s: %w", dnsNamespace, err), cleanupOnFailure())
		}
	}
	if resolved.WorkflowsEnabled {
		if err := helm.EnsureNamespace(ctx, o.HelmRun, opts.KubeconfigPath, workflowsNamespace, nil); err != nil {
			return nil, checks, failInstall(fmt.Errorf("install: prepare workflows namespace %s: %w", workflowsNamespace, err), cleanupOnFailure())
		}
		if err := helm.EnsureNamespace(ctx, o.HelmRun, opts.KubeconfigPath, workflowsBuildNamespace, helm.RestrictedNamespaceLabels()); err != nil {
			return nil, checks, failInstall(fmt.Errorf("install: prepare workflows build namespace %s: %w", workflowsBuildNamespace, err), cleanupOnFailure())
		}
	}

	taskCount := 1
	if resolved.ArtifactEnabled || resolved.DNSEnabled || resolved.InferenceEnabled {
		taskCount++
	}
	if resolved.WorkflowsEnabled {
		taskCount++
	}

	parallelResults := make(chan parallelSetResult, taskCount)
	var parallelWG sync.WaitGroup

	parallelWG.Add(1)
	go func() {
		defer parallelWG.Done()
		result := applyFreshRelease(ctx, o.HelmRun, opts.KubeconfigPath, applier, applicationSupportRelease)
		out := parallelSetResult{checks: result.checks, err: result.err}
		if result.rollback != nil {
			out.rollbacks = append(out.rollbacks, result.rollback)
		}
		parallelResults <- out
	}()

	if resolved.ArtifactEnabled || resolved.DNSEnabled || resolved.InferenceEnabled {
		parallelWG.Add(1)
		go func() {
			defer parallelWG.Done()
			var out parallelSetResult
			if resolved.ArtifactEnabled {
				registryKeys, keyErr := helm.EnsureRegistryPublicKeySecret(ctx, o.HelmRun, opts.KubeconfigPath,
					opts.ChartNamespace, "appliance-keys", registryNamespace, productconfig.DefaultRegistryPublicKeySecret)
				out.checks = append(out.checks, registryKeys.Checks...)
				if keyErr != nil {
					out.err = keyErr
					parallelResults <- out
					return
				}
				if cleanup := registryKeys.Cleanup; cleanup != nil {
					out.rollbacks = append(out.rollbacks, cleanup)
				}
				result := applyFreshRelease(ctx, o.HelmRun, opts.KubeconfigPath, applier, helm.ChartRelease{
					Name:       registryReleaseName,
					ChartPath:  resolved.RegistryChartPath,
					Namespace:  registryNamespace,
					ValuesPath: registryValuesPath,
				})
				out.checks = append(out.checks, result.checks...)
				if result.rollback != nil {
					out.rollbacks = append(out.rollbacks, result.rollback)
				}
				if result.err != nil {
					out.err = result.err
					parallelResults <- out
					return
				}
			}
			if resolved.DNSEnabled {
				result := applyFreshRelease(ctx, o.HelmRun, opts.KubeconfigPath, applier, dnsSupportRelease)
				out.checks = append(out.checks, result.checks...)
				if result.rollback != nil {
					out.rollbacks = append(out.rollbacks, result.rollback)
				}
				if result.err != nil {
					out.err = result.err
					parallelResults <- out
					return
				}
				if err := hostpackages.QuiesceStockDaemonUnits(); err != nil {
					out.err = err
					parallelResults <- out
					return
				}
				result = applyFreshRelease(ctx, o.HelmRun, opts.KubeconfigPath, applier, helm.ChartRelease{
					Name:            dnsReleaseName,
					ChartPath:       resolved.DNSChartPath,
					Namespace:       dnsNamespace,
					ValuesPath:      dnsValuesPath,
					NamespaceLabels: helm.PrivilegedNamespaceLabels(),
				})
				out.checks = append(out.checks, result.checks...)
				if result.rollback != nil {
					out.rollbacks = append(out.rollbacks, result.rollback)
				}
				if result.err != nil {
					out.err = result.err
					parallelResults <- out
					return
				}
			}
			if resolved.InferenceEnabled {
				result := applyFreshRelease(ctx, o.HelmRun, opts.KubeconfigPath, applier, helm.ChartRelease{
					Name:            inferenceReleaseName,
					ChartPath:       resolved.InferenceChartPath,
					Namespace:       inferenceNamespace,
					ValuesPath:      inferenceValuesPath,
					NamespaceLabels: helm.RestrictedNamespaceLabels(),
				})
				out.checks = append(out.checks, result.checks...)
				if result.rollback != nil {
					out.rollbacks = append(out.rollbacks, result.rollback)
				}
				if result.err != nil {
					out.err = result.err
					parallelResults <- out
					return
				}
			}
			parallelResults <- out
		}()
	}

	if resolved.WorkflowsEnabled {
		parallelWG.Add(1)
		go func() {
			defer parallelWG.Done()
			var out parallelSetResult
			result := applyFreshRelease(ctx, o.HelmRun, opts.KubeconfigPath, applier, workflowsSupportRelease)
			out.checks = append(out.checks, result.checks...)
			if result.rollback != nil {
				out.rollbacks = append(out.rollbacks, result.rollback)
			}
			if result.err != nil {
				out.err = result.err
				parallelResults <- out
				return
			}
			workflowsCRDChecks, applyErr := applyManifestFiles(ctx, clusterRun, opts.KubeconfigPath, resolved.WorkflowsCRDPaths, "workflows-crd")
			out.checks = append(out.checks, workflowsCRDChecks...)
			if applyErr != nil {
				out.err = applyErr
				parallelResults <- out
				return
			}
			result = applyFreshRelease(ctx, o.HelmRun, opts.KubeconfigPath, applier, helm.ChartRelease{
				Name:      workflowsReleaseName,
				ChartPath: resolved.WorkflowsChartPath,
				Namespace: workflowsNamespace,
			})
			out.checks = append(out.checks, result.checks...)
			if result.rollback != nil {
				out.rollbacks = append(out.rollbacks, result.rollback)
			}
			if result.err != nil {
				out.err = result.err
				parallelResults <- out
				return
			}
			parallelResults <- out
		}()
	}

	parallelWG.Wait()
	close(parallelResults)
	var parallelRollbacks []func() error
	var parallelErr error
	for result := range parallelResults {
		checks = append(checks, result.checks...)
		parallelRollbacks = append(parallelRollbacks, result.rollbacks...)
		if result.err != nil && parallelErr == nil {
			parallelErr = result.err
		}
	}
	if parallelErr != nil {
		return nil, checks, failInstall(fmt.Errorf("install: %w", parallelErr), cleanupOnFailure(parallelRollbacks...))
	}
	rollbacks = append(rollbacks, parallelRollbacks...)

	// Re-attach image-pull secrets to ServiceAccounts created by charts after the
	// first pass (for example workflow-controller SA in the workflows namespace).
	if strings.TrimSpace(opts.ImagePullRegistry.Registry) != "" {
		reconcilePull, reconcileErr := helm.EnsureImagePullSecrets(ctx, o.HelmRun, opts.KubeconfigPath, opts.ImagePullRegistry,
			productconfig.ProductNamespaces(opts.ChartNamespace)...)
		checks = append(checks, reconcilePull.Checks...)
		if reconcileErr != nil {
			return nil, checks, failInstall(fmt.Errorf("install: reconcile image-pull secrets: %w", reconcileErr), cleanupOnFailure())
		}
	}

	zonctlRollback, err := zonctlhost.Install(zonctlhost.InstallSpec{
		SourceBinaryPath:  resolved.ZonctlBinaryPath,
		RealDestPath:      opts.ZonctlRealDestPath,
		LauncherDestPath:  opts.ZonctlLauncherDestPath,
		HelperSourcePaths: resolved.HelperBinaryPaths,
	})
	if err != nil {
		var cleanupErr error
		if !opts.PreserveFailedState {
			cleanupErr = applier.Rollback(ctx, opts.ChartReleaseName, true)
			cleanupErr = errors.Join(cleanupErr, runRollbacks())
		}
		return nil, checks, failInstall(fmt.Errorf("install: install host zonctl: %w", err), cleanupErr)
	}
	rollbacks = append(rollbacks, zonctlRollback)

	now := time.Now().UTC()
	installed := &state.InstalledState{
		SchemaVersion:       1,
		ApplianceInstanceID: newApplianceInstanceID(),
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
			MetadataVersion:       metadataVersion,
			MetadataDigest:        metadataDigest,
		},
		K3sOwnership: state.K3sOwnership{Owned: true, OwnerApplianceVersion: targetVersion},
		LastOperation: state.Operation{
			Type:          "install",
			Status:        "completed",
			TransactionID: opts.TransactionID,
			StartedAt:     now,
			CompletedAt:   &now,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := state.Save(opts.InstalledStatePath, installed); err != nil {
		var cleanupErr error
		if !opts.PreserveFailedState {
			cleanupErr = applier.Rollback(ctx, opts.ChartReleaseName, true)
			cleanupErr = errors.Join(cleanupErr, runRollbacks())
		}
		return nil, checks, failInstall(fmt.Errorf("install: %w", err), cleanupErr)
	}

	return installed, checks, nil
}

// preferredLocalIPv4 returns the first candidate that parses as a literal
// IPv4 address, used for host DNS prepare and CoreDNS NS glue. Hostnames and
// IPv6 literals are skipped.
func hostDNSPrepareConfig(opts Options) hostdns.PrepareConfig {
	hostname := strings.TrimSpace(opts.NodeName)
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = strings.TrimSpace(h)
		}
	}
	aliases := make([]string, 0, 1+len(opts.TLSSANs))
	if identity, err := productconfig.ResolveApplianceIdentity(opts.ApplianceName, opts.DNSZone); err == nil {
		aliases = append(aliases, identity.FQDN)
	}
	aliases = append(aliases, opts.TLSSANs...)
	return hostdns.PrepareConfig{
		Hostname: hostname,
		IPv4:     preferredLocalIPv4(opts.TLSSANs...),
		Aliases:  aliases,
	}
}

func preferredLocalIPv4(candidates ...string) string {
	return hostdns.PreferredLocalIPv4(candidates...)
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// writeImagePullRegistries writes optional K3s registries.yaml when
// ImagePullRegistry.Registry is set. No-op when unset (air-gap preload-only).
func writeImagePullRegistries(o *Orchestrator, opts Options, checks *[]evidence.Check) error {
	if strings.TrimSpace(opts.ImagePullRegistry.Registry) == "" {
		return nil
	}
	path := strings.TrimSpace(opts.K3sRegistriesPath)
	if path == "" {
		return fmt.Errorf("install: image pull registry configured but K3sRegistriesPath is empty")
	}
	cfg := opts.ImagePullRegistry
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("install: image pull registry: %w", err)
	}
	if o.K3s.WriteRegistries == nil {
		return fmt.Errorf("install: WriteRegistries is not configured")
	}
	if err := o.K3s.WriteRegistries(path, cfg); err != nil {
		return fmt.Errorf("install: write k3s registries.yaml: %w", err)
	}
	*checks = append(*checks, evidence.Check{
		ID: "k3s-image-pull-registries", Category: "k3s", Status: evidence.StatusPass,
		Message:   fmt.Sprintf("wrote image-pull registries.yaml for %s", cfg.Registry),
		Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	})
	return nil
}

func k3sArtifactsAbsent(paths ...string) bool {
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil || !os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func applyManifestFiles(ctx context.Context, run cli.Runner, kubeconfig string, manifestPaths []string, checkPrefix string) ([]evidence.Check, error) {
	checks := make([]evidence.Check, 0, len(manifestPaths))
	for _, manifestPath := range manifestPaths {
		check := evidence.Check{
			ID:              checkPrefix + "-" + evidence.SanitizeIDSegment(filepath.Base(manifestPath)),
			Category:        "chart",
			Timestamp:       time.Now().UTC(),
			Idempotent:      true,
			SecretsRedacted: true,
		}
		if _, err := os.Stat(manifestPath); err != nil {
			check.Status = evidence.StatusFail
			check.Message = fmt.Sprintf("required artifact missing: %v", err)
			checks = append(checks, check)
			return checks, fmt.Errorf("apply kubernetes manifest %s: %w", manifestPath, err)
		}
		if _, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", manifestPath); err != nil {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			checks = append(checks, check)
			return checks, fmt.Errorf("apply kubernetes manifest %s: %w", manifestPath, err)
		}
		check.Status = evidence.StatusPass
		check.Message = fmt.Sprintf("applied %s", filepath.Base(manifestPath))
		checks = append(checks, check)
	}
	return checks, nil
}

// StageMetadataBundle copies the signed metadata-bundle archive into archiveDestDir
// for audit, extracts it under hostExtractDir for the control-plane hostPath
// mount, and validates profileID against the policy profiles catalog.
func StageMetadataBundle(archivePath, archiveDestDir, hostExtractDir, profileID string) (metadataVersion, digest string, err error) {
	archivePath = strings.TrimSpace(archivePath)
	if archivePath == "" {
		return "", "", fmt.Errorf("metadata bundle archive path is empty")
	}
	seeded, err := metadatabundle.SeedHost(archivePath, archiveDestDir, hostExtractDir, profileID)
	if err != nil {
		return "", "", err
	}
	return seeded.MetadataVersion, seeded.Digest, nil
}

func stageMetadataBundle(archivePath, archiveDestDir, hostExtractDir, profileID string) (metadataVersion, digest string, err error) {
	return StageMetadataBundle(archivePath, archiveDestDir, hostExtractDir, profileID)
}

func joinCleanupError(primary, cleanup error) error {
	if cleanup == nil {
		return primary
	}
	return errors.Join(primary, fmt.Errorf("install cleanup failed: %w", cleanup))
}

// wipeK3sDataDir removes leftover K3s etcd/server state preserved by
// uninstall so a fresh install can re-pin pod/service CIDRs safely.
func wipeK3sDataDir(dataDir string) error {
	dataDir = filepath.Clean(strings.TrimSpace(dataDir))
	if dataDir == "" || dataDir == "." || dataDir == string(filepath.Separator) || !filepath.IsAbs(dataDir) {
		return fmt.Errorf("refusing to wipe invalid k3s data dir %q", dataDir)
	}
	if err := os.RemoveAll(dataDir); err != nil {
		return err
	}
	return nil
}

func applyFreshRelease(ctx context.Context, run cli.Runner, kubeconfig string, applier *helm.Applier, rel helm.ChartRelease) freshReleaseResult {
	prepared, err := helm.EnsureReleasePrereqs(ctx, run, kubeconfig, rel)
	if err != nil {
		return freshReleaseResult{checks: prepared.Checks, err: err}
	}

	checks := append([]evidence.Check{}, prepared.Checks...)
	rollback := func() error {
		return errors.Join(
			applier.RollbackInNamespace(ctx, rel.Name, rel.Namespace, true),
			prepared.Cleanup(),
		)
	}
	chartCheck, err := applier.InstallOrUpgrade(ctx, rel)
	checks = append(checks, chartCheck)
	if err != nil {
		checks = append(checks, helm.CollectFailureDiagnostics(ctx, run, kubeconfig, rel)...)
		return freshReleaseResult{checks: checks, rollback: rollback, err: err}
	}

	return freshReleaseResult{
		checks:   checks,
		rollback: rollback,
	}
}

func newApplianceInstanceID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func toEvidenceChecks(checks []preflight.Check) []evidence.Check {
	out := make([]evidence.Check, 0, len(checks))
	for _, c := range checks {
		out = append(out, evidence.Check{
			ID:              c.ID,
			Category:        c.Category,
			Status:          evidence.Status(c.Status),
			Message:         c.Message,
			Remediation:     c.Remediation,
			Timestamp:       c.Timestamp,
			DurationMs:      c.DurationMs,
			Idempotent:      true,
			SecretsRedacted: true,
		})
	}
	return out
}
