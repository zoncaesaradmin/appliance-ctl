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

	InstalledStatePath     string
	K3sConfigPath          string
	K3sUnitPath            string
	K3sBinaryDestPath      string
	K3sUnitName            string
	K3sDataDir             string
	KubeconfigPath         string
	ApplianceProfile       string
	BuildCatalogPath       string
	SourceCredentialsPath  string
	NodeName               string
	TLSSANs                []string
	ZonctlRealDestPath     string
	ZonctlLauncherDestPath string

	ChartReleaseName string
	ChartNamespace   string

	BackupRoot    string
	TransactionID string
}

// Orchestrator holds the injectable adapters Upgrade drives.
type Orchestrator struct {
	K3s       k3s.Ops
	ImagesRun cli.Runner
	HelmRun   cli.Runner
}

// NewOrchestrator wires an Orchestrator to the real adapters.
func NewOrchestrator() *Orchestrator {
	return &Orchestrator{K3s: k3s.DefaultOps(), ImagesRun: cli.Exec, HelmRun: cli.Exec}
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
	preparedValuesPath, cleanupPreparedValues, err := productconfig.PrepareValuesFile(resolved.ConfigurationPath, effectiveProfile, opts.BuildCatalogPath)
	if err != nil {
		return nil, checks, fmt.Errorf("upgrade: %w", err)
	}
	defer cleanupPreparedValues()
	productSourceCredentialSecrets, err := productconfig.LoadSourceCredentialSecrets(opts.SourceCredentialsPath, "appliance-builds")
	if err != nil {
		return nil, checks, fmt.Errorf("upgrade: %w", err)
	}
	if err := productconfig.ValidateSourceCredentialProvisioning(opts.BuildCatalogPath, productSourceCredentialSecrets); err != nil {
		return nil, checks, fmt.Errorf("upgrade: %w", err)
	}
	sourceCredentialSecrets := toHelmSourceCredentialSecrets(productSourceCredentialSecrets)

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
	imgs := append(append([]images.Image{}, resolved.K3sImages...), resolved.OCIImages...)
	preloadResult, err := importer.PreloadAll(ctx, imgs)
	checks = append(checks, preloadResult.Checks...)
	if err != nil {
		_ = importer.Rollback(ctx, preloadResult.NewlyImported)
		checks = append(checks, rollback()...)
		return nil, checks, fmt.Errorf("upgrade: %w (rolled back to pre-upgrade backup)", err)
	}

	k3sVersionChanged := resolved.Compatibility.K3sVersion != installed.Components.K3sVersion
	binaryCheck := evidence.Check{ID: "upgrade-k3s-binary", Category: "k3s", Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true}
	if k3sVersionChanged {
		for _, path := range []string{opts.K3sBinaryDestPath, opts.K3sConfigPath, opts.K3sUnitPath} {
			if err := snapshotFile(path); err != nil {
				_ = importer.Rollback(ctx, preloadResult.NewlyImported)
				checks = append(checks, rollback()...)
				return nil, checks, fmt.Errorf("upgrade: preserve current k3s files: %w (rolled back to pre-upgrade backup)", err)
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
				_ = importer.Rollback(ctx, preloadResult.NewlyImported)
				checks = append(checks, rollback()...)
				return nil, checks, fmt.Errorf("upgrade: %s k3s: %w (rolled back to pre-upgrade backup)", step.name, err)
			}
		}
		binaryCheck.Status = evidence.StatusPass
		binaryCheck.Message = fmt.Sprintf("k3s upgraded from %s to %s", installed.Components.K3sVersion, resolved.Compatibility.K3sVersion)
	} else {
		binaryCheck.Status = evidence.StatusPass
		binaryCheck.Message = "k3s version unchanged; binary not replaced"
	}
	checks = append(checks, binaryCheck)

	var sourcePrepared helm.PreparedRelease
	cleanupSourceCredentials := func() {
		_ = sourcePrepared.Cleanup()
	}
	if len(sourceCredentialSecrets) > 0 {
		var prepErr error
		sourcePrepared, prepErr = helm.EnsureSourceCredentialSecrets(ctx, o.HelmRun, opts.KubeconfigPath, sourceCredentialSecrets)
		checks = append(checks, sourcePrepared.Checks...)
		if prepErr != nil {
			cleanupSourceCredentials()
			_ = importer.Rollback(ctx, preloadResult.NewlyImported)
			checks = append(checks, rollback()...)
			return nil, checks, fmt.Errorf("upgrade: %w (rolled back to pre-upgrade backup)", prepErr)
		}
	}

	prepared, err := helm.EnsureReleasePrereqs(ctx, o.HelmRun, opts.KubeconfigPath, helm.ChartRelease{
		Name:       opts.ChartReleaseName,
		ChartPath:  chartPath,
		Namespace:  opts.ChartNamespace,
		ValuesPath: preparedValuesPath,
	})
	checks = append(checks, prepared.Checks...)
	if err != nil {
		cleanupSourceCredentials()
		_ = importer.Rollback(ctx, preloadResult.NewlyImported)
		checks = append(checks, rollback()...)
		return nil, checks, fmt.Errorf("upgrade: %w (rolled back to pre-upgrade backup)", err)
	}

	readinessChecks, err := helm.EnsureClusterBaseline(ctx, o.HelmRun, opts.KubeconfigPath, preparedValuesPath)
	checks = append(checks, readinessChecks...)
	if err != nil {
		cleanupSourceCredentials()
		_ = importer.Rollback(ctx, preloadResult.NewlyImported)
		checks = append(checks, rollback()...)
		return nil, checks, fmt.Errorf("upgrade: %w (rolled back to pre-upgrade backup)", err)
	}

	applier := &helm.Applier{Run: o.HelmRun, Kubeconfig: opts.KubeconfigPath}
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
		cleanupSourceCredentials()
		_ = prepared.Cleanup()
		_ = applier.Rollback(ctx, opts.ChartReleaseName, false)
		_ = importer.Rollback(ctx, preloadResult.NewlyImported)
		checks = append(checks, rollback()...)
		return nil, checks, fmt.Errorf("upgrade: %w (rolled back to pre-upgrade backup)", err)
	}
	zonctlRollback, err := zonctlhost.Install(zonctlhost.InstallSpec{
		SourceBinaryPath: resolved.ZonctlBinaryPath,
		RealDestPath:     opts.ZonctlRealDestPath,
		LauncherDestPath: opts.ZonctlLauncherDestPath,
	})
	if err != nil {
		cleanupSourceCredentials()
		_ = prepared.Cleanup()
		_ = applier.Rollback(ctx, opts.ChartReleaseName, false)
		_ = importer.Rollback(ctx, preloadResult.NewlyImported)
		checks = append(checks, rollback()...)
		return nil, checks, fmt.Errorf("upgrade: install host zonctl: %w (rolled back to pre-upgrade backup)", err)
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
		_ = zonctlRollback()
		cleanupSourceCredentials()
		_ = prepared.Cleanup()
		_ = applier.Rollback(ctx, opts.ChartReleaseName, false)
		_ = importer.Rollback(ctx, preloadResult.NewlyImported)
		checks = append(checks, rollback()...)
		return nil, checks, fmt.Errorf("upgrade: %w (rolled back to pre-upgrade backup)", err)
	}

	return updated, checks, nil
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

func toHelmSourceCredentialSecrets(loaded []productconfig.SourceCredentialSecret) []helm.SourceCredentialSecret {
	out := make([]helm.SourceCredentialSecret, 0, len(loaded))
	for _, cred := range loaded {
		out = append(out, helm.SourceCredentialSecret{Namespace: cred.Namespace, SecretName: cred.SecretName, PrivateKeyPath: cred.PrivateKeyPath, KnownHostsSecretName: cred.KnownHostsSecretName, KnownHostsPath: cred.KnownHostsPath})
	}
	return out
}
