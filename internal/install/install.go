package install

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/bootstrapadmin"
	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/helm"
	"github.com/zoncaesaradmin/appliance-ctl/internal/host"
	"github.com/zoncaesaradmin/appliance-ctl/internal/images"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/preflight"
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
)

// Options fully parameterizes a fresh install. Every path is explicit
// (no hidden defaults inside this package) so tests can point every
// mutating operation at a temp directory; cmd/zonctl is responsible for
// filling in the real system paths. Artifact resolution is the caller's
// Source, not part of Options.
type Options struct {
	ApplianceVersion string

	InstalledStatePath string
	K3sConfigPath      string
	K3sUnitPath        string
	K3sBinaryDestPath  string
	K3sUnitName        string
	// K3sDataDir is K3s's own data directory (e.g. /var/lib/rancher/k3s),
	// distinct from K3sConfigPath. It backs the "data-dir" config key,
	// the preflight disk-space check, and is what `zonctl backup`
	// snapshots.
	K3sDataDir             string
	KubeconfigPath         string
	NodeName               string
	TLSSANs                []string
	ZonctlRealDestPath     string
	ZonctlLauncherDestPath string
	BootstrapAdminUser     string
	BootstrapAdminPassword []byte

	ChartReleaseName string
	ChartNamespace   string

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
}

// Orchestrator holds the injectable adapters Install drives. Tests
// construct one with fakes; production code uses NewOrchestrator.
type Orchestrator struct {
	K3s             k3s.Ops
	ImagesRun       cli.Runner
	HelmRun         cli.Runner
	ClusterRun      cli.Runner      // kubectl calls used to inspect an existing cluster before adopting it
	ClusterRunInput cli.InputRunner // kubectl calls that must pass protected stdin
	DetectHost      func(host.Options) (host.Facts, error)
}

// NewOrchestrator wires an Orchestrator to the real K3s, ctr, helm/kubectl,
// and host-detection adapters.
func NewOrchestrator() *Orchestrator {
	return &Orchestrator{K3s: k3s.DefaultOps(), ImagesRun: cli.Exec, HelmRun: cli.Exec, ClusterRun: cli.Exec, ClusterRunInput: cli.ExecInput, DetectHost: host.Detect}
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

	resolved, resolveChecks, err := source.Resolve(ctx)
	checks = append(checks, resolveChecks...)
	if err != nil {
		return nil, checks, err
	}
	targetVersion := strings.TrimSpace(resolved.BundleVersion)
	if targetVersion == "" {
		targetVersion = strings.TrimSpace(opts.ApplianceVersion)
	}
	if targetVersion == "" {
		return nil, checks, fmt.Errorf("install: resolved bundle version is empty")
	}

	signal, err := o.K3s.DetectService(opts.K3sUnitName)
	if err != nil {
		return nil, checks, fmt.Errorf("install: detect k3s service: %w", err)
	}

	facts, err := o.DetectHost(host.Options{DataDir: opts.K3sDataDir, RequiredPorts: preflight.RequiredPorts})
	if err != nil {
		return nil, checks, fmt.Errorf("install: detect host: %w", err)
	}
	if signal.Detected && signal.Active {
		facts.PortsInUse = map[int]string{}
	}
	preflightChecks := preflight.Run(facts)
	checks = append(checks, toEvidenceChecks(preflightChecks)...)
	if overall := preflight.OverallStatus(preflightChecks); overall == preflight.StatusOperatorAction || overall == preflight.StatusUnsupported {
		return nil, checks, fmt.Errorf("install: preflight blocked with status %q; resolve reported findings before installing", overall)
	}

	existing, err := state.Load(opts.InstalledStatePath)
	if err != nil {
		return nil, checks, fmt.Errorf("install: %w", err)
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

	// A fresh install always installs K3s. Adopting an existing cluster
	// only touches K3s if the running version doesn't match the target's
	// pinned version; a matching version is left alone entirely, and we
	// never register a stop-on-rollback for a service we didn't start.
	needsK3sInstall := decision == k3s.DecisionFreshInstall || signal.RunningVersion != resolved.Compatibility.K3sVersion
	if needsK3sInstall {
		if err := o.K3s.WriteConfig(opts.K3sConfigPath, k3s.Config{
			NodeName: opts.NodeName,
			DataDir:  opts.K3sDataDir,
			TLSSANs:  opts.TLSSANs,
		}); err != nil {
			return nil, checks, fmt.Errorf("install: write k3s config: %w", err)
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
			for _, path := range []string{opts.K3sUnitPath, opts.K3sBinaryDestPath, opts.K3sConfigPath} {
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					errs = append(errs, err)
				}
			}
			if err := o.K3s.DaemonReload(); err != nil {
				errs = append(errs, err)
			}
			return errors.Join(errs...)
		})
	}

	importer := &images.Importer{Run: o.ImagesRun, Namespace: "k8s.io"}

	// systemd reports the unit "started" as soon as the process launches,
	// well before K3s's embedded containerd actually accepts connections
	// on its socket; without this wait, PreloadAll below can hit a raw
	// "connection refused" on a freshly (re)started K3s.
	if err := importer.WaitReady(ctx, containerdReadyTimeout, containerdReadyPollInterval); err != nil {
		return nil, checks, joinCleanupError(fmt.Errorf("install: %w", err), runRollbacks())
	}

	imgs := append(append([]images.Image{}, resolved.K3sImages...), resolved.OCIImages...)
	preloadResult, err := importer.PreloadAll(ctx, imgs)
	checks = append(checks, preloadResult.Checks...)
	if err != nil {
		return nil, checks, joinCleanupError(fmt.Errorf("install: %w", err), runRollbacks())
	}
	rollbacks = append(rollbacks, func() error { return importer.Rollback(ctx, preloadResult.NewlyImported) })

	readinessChecks, err := helm.EnsureClusterBaseline(ctx, o.HelmRun, opts.KubeconfigPath, resolved.ConfigurationPath)
	checks = append(checks, readinessChecks...)
	if err != nil {
		return nil, checks, joinCleanupError(fmt.Errorf("install: %w", err), runRollbacks())
	}

	prepared, err := helm.EnsureReleasePrereqs(ctx, o.HelmRun, opts.KubeconfigPath, helm.ChartRelease{
		Name:       opts.ChartReleaseName,
		ChartPath:  resolved.ChartPath,
		Namespace:  opts.ChartNamespace,
		ValuesPath: resolved.ConfigurationPath,
	})
	checks = append(checks, prepared.Checks...)
	if err != nil {
		return nil, checks, joinCleanupError(fmt.Errorf("install: %w", err), runRollbacks())
	}
	rollbacks = append(rollbacks, prepared.Cleanup)

	applier := &helm.Applier{Run: o.HelmRun, Kubeconfig: opts.KubeconfigPath}
	chartCheck, err := applier.InstallOrUpgrade(ctx, helm.ChartRelease{
		Name:       opts.ChartReleaseName,
		ChartPath:  resolved.ChartPath,
		Namespace:  opts.ChartNamespace,
		ValuesPath: resolved.ConfigurationPath,
	})
	checks = append(checks, chartCheck)
	if err != nil {
		checks = append(checks, helm.CollectFailureDiagnostics(ctx, o.HelmRun, opts.KubeconfigPath, helm.ChartRelease{
			Name:       opts.ChartReleaseName,
			ChartPath:  resolved.ChartPath,
			Namespace:  opts.ChartNamespace,
			ValuesPath: resolved.ConfigurationPath,
		})...)
		cleanupErr := applier.Rollback(ctx, opts.ChartReleaseName, true)
		cleanupErr = errors.Join(cleanupErr, runRollbacks())
		return nil, checks, joinCleanupError(fmt.Errorf("install: %w", err), cleanupErr)
	}
	zonctlRollback, err := zonctlhost.Install(zonctlhost.InstallSpec{
		SourceBinaryPath: resolved.ZonctlBinaryPath,
		RealDestPath:     opts.ZonctlRealDestPath,
		LauncherDestPath: opts.ZonctlLauncherDestPath,
	})
	if err != nil {
		cleanupErr := applier.Rollback(ctx, opts.ChartReleaseName, true)
		cleanupErr = errors.Join(cleanupErr, runRollbacks())
		return nil, checks, joinCleanupError(fmt.Errorf("install: install host zonctl: %w", err), cleanupErr)
	}
	rollbacks = append(rollbacks, zonctlRollback)

	now := time.Now().UTC()
	installed := &state.InstalledState{
		SchemaVersion:       1,
		ApplianceInstanceID: newApplianceInstanceID(),
		InstalledVersion:    targetVersion,
		InstalledReleaseID:  resolved.ReleaseID,
		Components: state.Components{
			K3sVersion:   resolved.Compatibility.K3sVersion,
			ChartVersion: resolved.Compatibility.ChartVersion,
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
		cleanupErr := applier.Rollback(ctx, opts.ChartReleaseName, true)
		cleanupErr = errors.Join(cleanupErr, runRollbacks())
		return nil, checks, joinCleanupError(fmt.Errorf("install: %w", err), cleanupErr)
	}

	// K3s, the chart, the host zonctl binary, and the installed-state
	// record are all fully in place at this point — there is a real,
	// running appliance to preserve from here on. A bootstrap failure
	// (e.g. a password rejected by the server's policy, or a transient
	// `kubectl exec` failure) must not roll any of that back; it's a
	// separately retriable step, not a reason to discard a successful
	// install. See ErrBootstrapFailed's doc comment for how callers
	// should treat this case.
	bootstrapRun := o.ClusterRunInput
	if bootstrapRun == nil {
		if o.ClusterRun != nil {
			bootstrapRun = func(ctx context.Context, _ []byte, name string, args ...string) (string, error) {
				return o.ClusterRun(ctx, name, args...)
			}
		} else {
			bootstrapRun = cli.ExecInput
		}
	}
	bootstrapCheck, err := bootstrapadmin.Init(ctx, bootstrapadmin.Options{
		Run:           bootstrapRun,
		Kubeconfig:    opts.KubeconfigPath,
		Namespace:     opts.ChartNamespace,
		ReleaseName:   opts.ChartReleaseName,
		AdminUsername: opts.BootstrapAdminUser,
		AdminPassword: opts.BootstrapAdminPassword,
	})
	checks = append(checks, bootstrapCheck)
	if err != nil {
		return installed, checks, fmt.Errorf("%w: %w", ErrBootstrapFailed, err)
	}

	return installed, checks, nil
}

// ErrBootstrapFailed marks a first-admin bootstrap failure that happened
// after K3s, the chart, the host zonctl binary, and the installed-state
// record were already successfully put in place. Unlike every other
// error Install can return, this one comes with a non-nil
// *state.InstalledState — the appliance genuinely is installed and
// running. Callers (cmd/zonctl) should report this as a successful
// install with a bootstrap warning, not a failed install, and point the
// operator at retrying just the bootstrap step.
var ErrBootstrapFailed = errors.New("first-admin bootstrap failed")

func joinCleanupError(primary, cleanup error) error {
	if cleanup == nil {
		return primary
	}
	return errors.Join(primary, fmt.Errorf("install cleanup failed: %w", cleanup))
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
