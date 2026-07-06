// Package repair implements the safe, bounded remediations the plan
// permits: bringing an owned K3s installation back to a running state.
// It never reinstalls, reformats, or otherwise touches durable data —
// anything beyond restarting a service this appliance already owns is
// out of scope and returns a clear error instead of guessing.
package repair

import (
	"context"
	"fmt"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

// Repair inspects the K3s service against the recorded installed-state
// and takes the one safe action it can: restart K3s if it is owned but
// not currently active. If installed-state does not record ownership at
// all, or the service is missing entirely (not just stopped), repair
// cannot safely proceed and returns an error directing the operator to
// `install` or `restore` instead.
func Repair(ctx context.Context, ops k3s.Ops, installed *state.InstalledState, unitName string) ([]evidence.Check, error) {
	now := time.Now().UTC()

	if installed == nil || !installed.K3sOwnership.Owned {
		check := evidence.Check{
			ID: "repair-k3s-service", Category: "k3s", Status: evidence.StatusFail,
			Message:   "no owned installation is recorded; repair cannot proceed without first running install or restore",
			Timestamp: now, Idempotent: true, SecretsRedacted: true,
		}
		return []evidence.Check{check}, fmt.Errorf("repair: %s", check.Message)
	}

	signal, err := ops.DetectService(unitName)
	if err != nil {
		return nil, fmt.Errorf("repair: detect k3s service: %w", err)
	}

	if !signal.Detected {
		check := evidence.Check{
			ID: "repair-k3s-service", Category: "k3s", Status: evidence.StatusFail,
			Message:   "installed-state records an owned K3s installation, but its service is missing entirely; this cannot be repaired, restore from backup",
			Timestamp: now, Idempotent: true, SecretsRedacted: true,
		}
		return []evidence.Check{check}, fmt.Errorf("repair: %s", check.Message)
	}

	if signal.Active {
		check := evidence.Check{
			ID: "repair-k3s-service", Category: "k3s", Status: evidence.StatusPass,
			Message:   "k3s is already active; nothing to repair",
			Timestamp: now, Idempotent: true, SecretsRedacted: true,
		}
		return []evidence.Check{check}, nil
	}

	if err := ops.Restart(unitName); err != nil {
		check := evidence.Check{
			ID: "repair-k3s-service", Category: "k3s", Status: evidence.StatusFail,
			Message:   fmt.Sprintf("failed to restart k3s: %v", err),
			Timestamp: now, Idempotent: true, SecretsRedacted: true,
		}
		return []evidence.Check{check}, fmt.Errorf("repair: restart k3s: %w", err)
	}

	check := evidence.Check{
		ID: "repair-k3s-service", Category: "k3s", Status: evidence.StatusPass,
		Message:   "k3s was stopped and has been restarted",
		Timestamp: now, Idempotent: true, SecretsRedacted: true,
	}
	return []evidence.Check{check}, nil
}
