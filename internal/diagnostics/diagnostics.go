// Package diagnostics aggregates installed-state and K3s health signals
// into evidence.v1 checks, shared by the `status`, `verify`, and
// `support-bundle` commands so they report a consistent picture of
// dependency health.
package diagnostics

import (
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

// Signals is what the caller has already gathered about the running
// installation; Evaluate only interprets it, never gathers it itself, so
// it is pure and trivially testable.
type Signals struct {
	// InstalledState is nil when the host has never been installed.
	InstalledState *state.InstalledState
	// InstalledStateErr is set when installed-state.json exists but
	// failed to load or validate (corruption, schema drift).
	InstalledStateErr error
	K3sHealth         k3s.HealthStatus
}

// Evaluate turns Signals into a list of evidence checks: one for
// installed-state and one for K3s health.
func Evaluate(sig Signals) []evidence.Check {
	now := time.Now().UTC()
	var checks []evidence.Check

	switch {
	case sig.InstalledStateErr != nil:
		checks = append(checks, evidence.Check{
			ID: "installed-state-valid", Category: "manifest", Status: evidence.StatusFail,
			Message: sig.InstalledStateErr.Error(), Timestamp: now, Idempotent: true, SecretsRedacted: true,
		})
	case sig.InstalledState == nil:
		checks = append(checks, evidence.Check{
			ID: "installed-state-present", Category: "manifest", Status: evidence.StatusFail,
			Message: "no installed-state record found; the appliance is not installed", Timestamp: now, Idempotent: true, SecretsRedacted: true,
		})
	default:
		checks = append(checks, evidence.Check{
			ID: "installed-state-present", Category: "manifest", Status: evidence.StatusPass,
			Message:   "installed-state present: version " + sig.InstalledState.InstalledVersion,
			Timestamp: now, Idempotent: true, SecretsRedacted: true,
		})
	}

	k3sStatus := evidence.StatusPass
	message := "k3s is healthy"
	if !sig.K3sHealth.Healthy {
		k3sStatus = evidence.StatusFail
		message = strings.Join(sig.K3sHealth.Reasons, "; ")
	}
	checks = append(checks, evidence.Check{
		ID: "k3s-health", Category: "k3s", Status: k3sStatus,
		Message: message, Timestamp: now, Idempotent: true, SecretsRedacted: true,
	})

	return checks
}
