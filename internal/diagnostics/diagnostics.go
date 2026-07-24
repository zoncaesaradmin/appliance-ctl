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
	// ChartHealth and IngressHealth are only populated when the caller
	// actually reached far enough to check them (installed-state present
	// and K3s active). Checked distinguishes "not checked" from "checked
	// and unhealthy" so a not-yet-installed or K3s-down host doesn't get
	// a misleading chart/ingress failure on top of the real cause.
	ChartHealth     ChartHealth
	RegistryHealth  ChartHealth
	RegistryStorage ChartHealth
	IngressHealth   IngressHealth
}

// ChartHealth reports whether the appliance's Helm release is deployed.
type ChartHealth struct {
	Checked bool
	Healthy bool
	Message string
}

// IngressHealth reports whether at least one IngressRoute exists for the
// appliance's namespace — the exact signal that was missing in the
// incident that motivated this check: Helm and K3s both reported
// healthy while no route existed to send traffic to the appliance pod.
type IngressHealth struct {
	Checked bool
	Present bool
	Message string
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

	if sig.ChartHealth.Checked {
		status := evidence.StatusPass
		if !sig.ChartHealth.Healthy {
			status = evidence.StatusFail
		}
		checks = append(checks, evidence.Check{
			ID: "chart-release-health", Category: "chart", Status: status,
			Message: sig.ChartHealth.Message, Timestamp: now, Idempotent: true, SecretsRedacted: true,
		})
	}
	if sig.RegistryHealth.Checked {
		status := evidence.StatusPass
		if !sig.RegistryHealth.Healthy {
			status = evidence.StatusFail
		}
		checks = append(checks, evidence.Check{
			ID: "registry-release-health", Category: "chart", Status: status,
			Message: sig.RegistryHealth.Message, Timestamp: now, Idempotent: true, SecretsRedacted: true,
		})
	}
	if sig.RegistryStorage.Checked {
		status := evidence.StatusPass
		if !sig.RegistryStorage.Healthy {
			status = evidence.StatusFail
		}
		checks = append(checks, evidence.Check{
			ID: "registry-storage-bound", Category: "storage", Status: status,
			Message: sig.RegistryStorage.Message, Timestamp: now, Idempotent: true, SecretsRedacted: true,
		})
	}

	if sig.IngressHealth.Checked {
		status := evidence.StatusPass
		if !sig.IngressHealth.Present {
			status = evidence.StatusFail
		}
		checks = append(checks, evidence.Check{
			ID: "ingress-route-present", Category: "chart", Status: status,
			Message: sig.IngressHealth.Message, Timestamp: now, Idempotent: true, SecretsRedacted: true,
		})
	}

	return checks
}
