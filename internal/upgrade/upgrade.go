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
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdirs"
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

	InstalledStatePath string
	K3sConfigPath      string
	K3sUnitPath        string
	K3sBinaryDestPath  string
	K3sUnitName        string
	K3sDataDir         string
	KubeconfigPath     string
	ApplianceProfile   string
	BuildCatalogPath   string
	// WorkspaceRootDir is the host directory backing the workspace
	// storage hostPath PersistentVolume (builder profile only). See
	// internal/hostdirs — re-applied on every upgrade so a host whose
	// directory was created before this fix shipped self-heals.
	WorkspaceRootDir       string
	NodeName               string
	TLSSANs                []string
	ZonctlRealDestPath     string
	ZonctlLauncherDestPath string

	ChartReleaseName string
	ChartNamespace   string

	BackupRoot    string
	TransactionID string

	// PreserveFailedState disables rollback-to-backup on failure so the
	// partially upgraded host can be inspected in place for debugging.
	// The default remains rollback for normal operator use.
	PreserveFailedState bool
}

const (
	registryReleaseName = "appliance-registry"
	registryNamespace   = "registry"
	argoReleaseName     = "argo-workflows"
	argoNamespace       = "workflows"
)

// Orchestrator holds the injectable adapters Upgrade drives.
type Orchestrator struct {
	K3s       k3s.Ops
	ImagesRun cli.Runner
	HelmRun   cli.Runner
	// EnsureOwnedDir prepares a host directory backing a static hostPath
	// PersistentVolume with the correct owner; see internal/hostdirs.
	EnsureOwnedDir func(path string, uid, gid int, perm os.FileMode) error
}

// NewOrchestrator wires an Orchestrator to the real adapters.
func NewOrchestrator() *Orchestrator {
	return &Orchestrator{
		K3s: k3s.DefaultOps(), ImagesRun: cli.Exec, HelmRun: cli.Exec,
		EnsureOwnedDir: func(path string, uid, gid int, perm os.FileMode) error {
			return hostdirs.EnsureOwnedDir(path, uid, gid, perm, os.Chown)
		},
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

	resolved, resolveChecks, err := source.Resolve(ctx)
	checks = append(checks, resolveChecks...)
	if err != nil {
		return nil, checks, fmt.Errorf("upgrade: %w", err)
	}
	targetVersion := strings.TrimSpace(resolved.BundleVersion)
	if targetVersion == "" {
		targetVersion = strings.TrimSpace(opts.TargetApplianceVersion)
	}
	if targetVersion == "" {
		return nil, checks, fmt.Errorf("upgrade: resolved bundle version is empty")
	}
	sameVersionRefresh := strings.TrimSpace(installed.InstalledVersion) == targetVersion

	effectiveProfile, err := productconfig.ResolveApplianceProfile(opts.ApplianceProfile, installed.ApplianceProfile)
	if err != nil {
		return nil, checks, fmt.Errorf("upgrade: %w", err)
	}
	preparedValuesPath, cleanupPreparedValues, err := productconfig.PrepareValuesFile(resolved.ConfigurationPath, effectiveProfile, opts.BuildCatalogPath, resolved.WorkspaceProvisionerImageReference, resolved.BuilderImageReference, resolved.ZotImageReference)
	if err != nil {
		return nil, checks, fmt.Errorf("upgrade: %w", err)
	}
	defer cleanupPreparedValues()
	registryValuesPath := ""
	cleanupRegistryValues := func() {}
	if productconfig.HasCapability(effectiveProfile, productconfig.CapabilityArtifact) {
		registryValuesPath, cleanupRegistryValues, err = productconfig.PrepareRegistryValuesFile(filepath.Dir(resolved.ConfigurationPath), resolved.ZotImageReference, firstUpgradeString(opts.TLSSANs))
		if err != nil {
			return nil, checks, fmt.Errorf("upgrade: %w", err)
		}
		defer cleanupRegistryValues()
	}

	// Gated on the Build capability, not the "builder" profile name
	// directly: more than one profile can enable Build, and this
	// directory only needs to exist when Build does. Re-applied on every
	// upgrade (not just once at install time) so a host whose workspace
	// directory was created before this fix shipped — or whose ownership
	// drifted for any other reason — self-heals here rather than needing
	// a manual chown. See internal/hostdirs for why this can't be left
	// to Kubernetes' own fsGroup handling.
	if productconfig.HasCapability(effectiveProfile, productconfig.CapabilityBuild) && opts.WorkspaceRootDir != "" {
		if err := o.EnsureOwnedDir(opts.WorkspaceRootDir, hostdirs.ApplianceDirOwnerUID, hostdirs.ApplianceSharedFSGID, hostdirs.WorkspaceDirMode); err != nil {
			return nil, checks, fmt.Errorf("upgrade: prepare workspace directory: %w", err)
		}
		checks = append(checks, evidence.Check{
			ID: "workspace-directory-owned", Category: "host", Status: evidence.StatusPass,
			Message:   fmt.Sprintf("%s owned by %d:%d", opts.WorkspaceRootDir, hostdirs.ApplianceDirOwnerUID, hostdirs.ApplianceSharedFSGID),
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
	}

	if !sameVersionRefresh && !isSupportedSource(installed.InstalledVersion, resolved.Compatibility.SupportedUpgradeSources) {
		return nil, checks, fmt.Errorf("upgrade: %s is not a supported upgrade source for target %s (supported: %v)", installed.InstalledVersion, targetVersion, resolved.Compatibility.SupportedUpgradeSources)
	}
	k3sBinarySrc := resolved.K3sBinaryPath
	chartPath := resolved.ChartPath

	// Mandatory pre-upgrade recovery set.
	backupManifest, backupChecks, err := backup.Create(ctx, o.K3s, opts.K3sUnitName, opts.K3sDataDir, opts.BackupRoot, installed.InstalledVersion)
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
		restoreChecks, restoreErr := backup.Restore(ctx, o.K3s, opts.K3sUnitName, backupDir, opts.K3sDataDir)
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
	imgs := append(append([]images.Image{}, resolved.K3sImages...), upgradeProfileOCIImages(resolved.OCIImages, effectiveProfile)...)
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
		for _, path := range []string{opts.K3sBinaryDestPath, opts.K3sConfigPath, opts.K3sUnitPath} {
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
				return o.K3s.WriteConfig(opts.K3sConfigPath, k3s.Config{NodeName: opts.NodeName, DataDir: opts.K3sDataDir, TLSSANs: opts.TLSSANs})
			}},
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
	}
	checks = append(checks, binaryCheck)

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

	applier := &helm.Applier{Run: o.HelmRun, Kubeconfig: opts.KubeconfigPath}
	if productconfig.HasCapability(effectiveProfile, productconfig.CapabilityArtifact) {
		if err := o.EnsureOwnedDir(hostdirs.RegistryLogDir, hostdirs.RegistryDirOwnerUID, hostdirs.ApplianceSharedFSGID, hostdirs.ServiceLogDirMode); err != nil {
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: prepare registry log directory: %w", err), rollback)
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
		checks = append(checks, evidence.Check{
			ID: "registry-log-directory-owned", Category: "host", Status: evidence.StatusPass,
			Message:   fmt.Sprintf("%s owned by %d:%d", hostdirs.RegistryLogDir, hostdirs.RegistryDirOwnerUID, hostdirs.ApplianceSharedFSGID),
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
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
			rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", registryErr), func() []evidence.Check {
				_ = registryKeys.Cleanup()
				_ = applier.Rollback(ctx, registryReleaseName, false)
				return rollback()
			})
			checks = append(checks, rollbackChecks...)
			return nil, checks, failErr
		}
	}
	if productconfig.HasCapability(effectiveProfile, productconfig.CapabilityWorkflows) {
		for _, crdPath := range resolved.ArgoCRDPaths {
			if _, applyErr := o.HelmRun(ctx, "kubectl", "--kubeconfig", opts.KubeconfigPath, "apply", "-f", crdPath); applyErr != nil {
				rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: apply Argo CRD %s: %w", crdPath, applyErr), rollback)
				checks = append(checks, rollbackChecks...)
				return nil, checks, failErr
			}
		}
		if resolved.ArgoChartPath != "" {
			argoCheck, argoErr := applier.InstallOrUpgrade(ctx, helm.ChartRelease{
				Name: argoReleaseName, ChartPath: resolved.ArgoChartPath, Namespace: argoNamespace,
			})
			checks = append(checks, argoCheck)
			if argoErr != nil {
				rollbackChecks, failErr := failUpgrade(fmt.Errorf("upgrade: %w", argoErr), func() []evidence.Check {
					_ = applier.Rollback(ctx, argoReleaseName, false)
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
	zonctlRollback, err := zonctlhost.Install(zonctlhost.InstallSpec{
		SourceBinaryPath: resolved.ZonctlBinaryPath,
		RealDestPath:     opts.ZonctlRealDestPath,
		LauncherDestPath: opts.ZonctlLauncherDestPath,
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
		Components: state.Components{
			K3sVersion:   resolved.Compatibility.K3sVersion,
			ChartVersion: resolved.Compatibility.ChartVersion,
			ZotVersion:   upgradeComponentZotVersion(effectiveProfile, resolved.Compatibility.ZotVersion),
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

func upgradeProfileOCIImages(all []images.Image, profile string) []images.Image {
	out := make([]images.Image, 0, len(all))
	for _, image := range all {
		if image.Category == images.CategoryDependency {
			if strings.HasPrefix(image.Name, "registry.local/zot@") &&
				!productconfig.HasCapability(profile, productconfig.CapabilityArtifact) {
				continue
			}
			if (strings.Contains(image.Name, "/argoproj/workflow-controller:") || strings.Contains(image.Name, "/argoproj/argoexec:")) &&
				!productconfig.HasCapability(profile, productconfig.CapabilityWorkflows) {
				continue
			}
		}
		out = append(out, image)
	}
	return out
}

func upgradeComponentZotVersion(profile, version string) string {
	if productconfig.HasCapability(profile, productconfig.CapabilityArtifact) {
		return version
	}
	return ""
}

func firstUpgradeString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
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
