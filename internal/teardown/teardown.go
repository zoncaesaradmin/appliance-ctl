// Package teardown implements uninstall (data-preserving) and
// factory-reset (destructive, separately guarded). "uninstall preserves
// appliance data by default. factory-reset requires a recent verified
// backup or a separately confirmed data-loss override." (docs/release-plan.md)
package teardown

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/zonctlhost"
)

// removeK3s stops the K3s service and removes the unit, binary, and
// config files this appliance installed. It never touches the data
// directory: that decision belongs to the caller (Uninstall preserves
// it; FactoryReset wipes it).
func removeK3s(ops k3s.Ops, unitName, binaryPath, configPath, unitPath, kubectlSymlinkPath, cniNetworkDir string, cniInterfaceNames []string) ([]evidence.Check, error) {
	var checks []evidence.Check

	stopStart := time.Now()
	if err := ops.Stop(unitName); err != nil {
		return checks, fmt.Errorf("teardown: stop k3s: %w", err)
	}
	checks = append(checks, evidence.Check{
		ID: "teardown-stop-k3s", Category: "k3s", Status: evidence.StatusPass,
		Message: "k3s stopped", Timestamp: stopStart.UTC(),
		DurationMs: time.Since(stopStart).Milliseconds(), Idempotent: true, SecretsRedacted: true,
	})

	if err := ops.CleanupNodeNetwork(cniNetworkDir, cniInterfaceNames); err != nil {
		checks = append(checks, evidence.Check{
			ID: "teardown-clean-k3s-network-state", Category: "k3s", Status: evidence.StatusFail,
			Message: err.Error(), Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
		return checks, fmt.Errorf("teardown: clean k3s network state: %w", err)
	}
	checks = append(checks, evidence.Check{
		ID: "teardown-clean-k3s-network-state", Category: "k3s", Status: evidence.StatusPass,
		Message: "stale K3s CNI/IPAM state removed", Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	})

	// Removed before the binary itself: RemoveKubectlSymlink only acts
	// when the symlink still points at binaryPath, so it must run while
	// that target still exists to identify. Left in place, it would
	// dangle after the binary is removed below and silently break every
	// future `kubectl` invocation — zonctl's own included — until the
	// next install happens to recreate it.
	if err := ops.RemoveKubectlSymlink(binaryPath, kubectlSymlinkPath); err != nil {
		checks = append(checks, evidence.Check{
			ID: "teardown-remove-kubectl-symlink", Category: "k3s", Status: evidence.StatusFail,
			Message: err.Error(), Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
		return checks, fmt.Errorf("teardown: remove kubectl symlink: %w", err)
	}

	for _, path := range []string{unitPath, binaryPath, configPath} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			checks = append(checks, evidence.Check{
				ID: "teardown-remove-" + evidence.SanitizeIDSegment(filepath.Base(path)), Category: "k3s", Status: evidence.StatusFail,
				Message: err.Error(), Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
			})
			return checks, fmt.Errorf("teardown: remove %s: %w", path, err)
		}
	}
	checks = append(checks, evidence.Check{
		ID: "teardown-remove-k3s-files", Category: "k3s", Status: evidence.StatusPass,
		Message: "k3s unit, binary, and config removed", Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	})

	// Without this, systemd's cached unit-file list (what DetectService's
	// presence check reads) keeps reporting the just-deleted unit as
	// present, and every subsequent install permanently sees an
	// "existing K3s cluster" and refuses to proceed without force-adopt.
	if err := ops.DaemonReload(); err != nil {
		checks = append(checks, evidence.Check{
			ID: "teardown-daemon-reload", Category: "k3s", Status: evidence.StatusFail,
			Message: err.Error(), Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
		return checks, fmt.Errorf("teardown: daemon-reload: %w", err)
	}
	checks = append(checks, evidence.Check{
		ID: "teardown-daemon-reload", Category: "k3s", Status: evidence.StatusPass,
		Message: "systemd unit-file cache refreshed", Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	})
	return checks, nil
}

// Uninstall removes K3s (service, binary, config) and the
// installed-state record, but leaves dataDir untouched: "uninstall
// preserves appliance data by default."
func Uninstall(ctx context.Context, ops k3s.Ops, unitName, installedStatePath, binaryPath, configPath, unitPath, kubectlSymlinkPath, cniNetworkDir string, cniInterfaceNames []string) ([]evidence.Check, error) {
	checks, err := removeK3s(ops, unitName, binaryPath, configPath, unitPath, kubectlSymlinkPath, cniNetworkDir, cniInterfaceNames)
	if err != nil {
		return checks, err
	}

	if err := os.Remove(installedStatePath); err != nil && !os.IsNotExist(err) {
		return checks, fmt.Errorf("teardown: remove installed-state: %w", err)
	}
	checks = append(checks, evidence.Check{
		ID: "teardown-preserve-data", Category: "backup-restore", Status: evidence.StatusPass,
		Message: "appliance data directory preserved", Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	})
	return checks, nil
}

// FactoryReset does everything Uninstall does, plus wipes dataDir,
// stateDir, and removes zonctl itself. It refuses outright unless
// recentBackupVerified or dataLossOverride is true: "factory-reset
// requires a recent verified backup or a separately confirmed
// data-loss override," never both silently assumed.
func FactoryReset(ctx context.Context, ops k3s.Ops, unitName, stateDir, binaryPath, configPath, unitPath, kubectlSymlinkPath, cniNetworkDir string, cniInterfaceNames []string, dataDir, zonctlRealPath, zonctlLauncherPath string, recentBackupVerified, dataLossOverride bool) ([]evidence.Check, error) {
	if !recentBackupVerified && !dataLossOverride {
		return nil, fmt.Errorf("teardown: factory-reset requires a recent verified backup or an explicit data-loss override")
	}

	checks, err := removeK3s(ops, unitName, binaryPath, configPath, unitPath, kubectlSymlinkPath, cniNetworkDir, cniInterfaceNames)
	if err != nil {
		return checks, err
	}

	if err := os.RemoveAll(dataDir); err != nil {
		return checks, fmt.Errorf("teardown: remove data directory: %w", err)
	}
	checks = append(checks, evidence.Check{
		ID: "teardown-wipe-data", Category: "backup-restore", Status: evidence.StatusPass,
		Message: "appliance data directory removed", Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	})

	// stateDir holds more than installed-state.json: the installer lock,
	// transaction journal, evidence history, support bundles, and —
	// notably — zonctl backup's own snapshots of appliance data.
	// "Factory reset" leaving old backups sitting on disk would defeat
	// the point, so this removes the whole directory, not just the one
	// file. The caller recreates it fresh (via MkdirAll) to persist this
	// very operation's own evidence report immediately afterward, which
	// is the one thing intentionally left behind: a receipt that a
	// factory-reset happened.
	if err := os.RemoveAll(stateDir); err != nil {
		return checks, fmt.Errorf("teardown: remove state directory: %w", err)
	}
	checks = append(checks, evidence.Check{
		ID: "teardown-wipe-state-dir", Category: "backup-restore", Status: evidence.StatusPass,
		Message:   "state directory removed (installer lock, transaction journal, evidence history, support bundles, backups)",
		Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	})

	// Last step, deliberately: every other check above has already
	// succeeded, so this is the one point of no return. Safe even though
	// it deletes the binary this very process is running from — see
	// zonctlhost.Uninstall's doc comment.
	if err := zonctlhost.Uninstall(zonctlRealPath, zonctlLauncherPath); err != nil {
		checks = append(checks, evidence.Check{
			ID: "teardown-remove-zonctl", Category: "manifest", Status: evidence.StatusFail,
			Message: err.Error(), Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		})
		return checks, fmt.Errorf("teardown: remove zonctl: %w", err)
	}
	checks = append(checks, evidence.Check{
		ID: "teardown-remove-zonctl", Category: "manifest", Status: evidence.StatusPass,
		Message: "zonctl removed from host", Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	})
	return checks, nil
}
