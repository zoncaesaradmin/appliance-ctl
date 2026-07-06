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
)

// removeK3s stops the K3s service and removes the unit, binary, and
// config files this appliance installed. It never touches the data
// directory: that decision belongs to the caller (Uninstall preserves
// it; FactoryReset wipes it).
func removeK3s(ops k3s.Ops, unitName, binaryPath, configPath, unitPath string) ([]evidence.Check, error) {
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

	for _, path := range []string{unitPath, binaryPath, configPath} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			checks = append(checks, evidence.Check{
				ID: "teardown-remove-" + filepath.Base(path), Category: "k3s", Status: evidence.StatusFail,
				Message: err.Error(), Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
			})
			return checks, fmt.Errorf("teardown: remove %s: %w", path, err)
		}
	}
	checks = append(checks, evidence.Check{
		ID: "teardown-remove-k3s-files", Category: "k3s", Status: evidence.StatusPass,
		Message: "k3s unit, binary, and config removed", Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	})
	return checks, nil
}

// Uninstall removes K3s (service, binary, config) and the
// installed-state record, but leaves dataDir untouched: "uninstall
// preserves appliance data by default."
func Uninstall(ctx context.Context, ops k3s.Ops, unitName, installedStatePath, binaryPath, configPath, unitPath string) ([]evidence.Check, error) {
	checks, err := removeK3s(ops, unitName, binaryPath, configPath, unitPath)
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

// FactoryReset does everything Uninstall does, plus wipes dataDir. It
// refuses outright unless recentBackupVerified or dataLossOverride is
// true: "factory-reset requires a recent verified backup or a
// separately confirmed data-loss override," never both silently assumed.
func FactoryReset(ctx context.Context, ops k3s.Ops, unitName, installedStatePath, binaryPath, configPath, unitPath, dataDir string, recentBackupVerified, dataLossOverride bool) ([]evidence.Check, error) {
	if !recentBackupVerified && !dataLossOverride {
		return nil, fmt.Errorf("teardown: factory-reset requires a recent verified backup or an explicit data-loss override")
	}

	checks, err := removeK3s(ops, unitName, binaryPath, configPath, unitPath)
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

	if err := os.Remove(installedStatePath); err != nil && !os.IsNotExist(err) {
		return checks, fmt.Errorf("teardown: remove installed-state: %w", err)
	}
	return checks, nil
}
