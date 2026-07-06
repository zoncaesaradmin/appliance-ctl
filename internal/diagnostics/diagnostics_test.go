package diagnostics_test

import (
	"errors"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/diagnostics"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

func statusOf(t *testing.T, checks []evidence.Check, id string) evidence.Status {
	t.Helper()
	for _, c := range checks {
		if c.ID == id {
			return c.Status
		}
	}
	t.Fatalf("no check with id %q found", id)
	return ""
}

func TestEvaluate_HealthyInstall(t *testing.T) {
	checks := diagnostics.Evaluate(diagnostics.Signals{
		InstalledState: &state.InstalledState{InstalledVersion: "2.4.0"},
		K3sHealth:      k3s.HealthStatus{Healthy: true},
	})
	if got := statusOf(t, checks, "installed-state-present"); got != evidence.StatusPass {
		t.Errorf("expected pass, got %s", got)
	}
	if got := statusOf(t, checks, "k3s-health"); got != evidence.StatusPass {
		t.Errorf("expected pass, got %s", got)
	}
	if evidence.OverallStatus(checks) != evidence.StatusPass {
		t.Errorf("expected overall pass")
	}
}

// Dependency failure: K3s itself is unhealthy even though the appliance
// is recorded as installed.
func TestEvaluate_K3sUnhealthy(t *testing.T) {
	checks := diagnostics.Evaluate(diagnostics.Signals{
		InstalledState: &state.InstalledState{InstalledVersion: "2.4.0"},
		K3sHealth:      k3s.HealthStatus{Healthy: false, Reasons: []string{"k3s service is not active"}},
	})
	if got := statusOf(t, checks, "k3s-health"); got != evidence.StatusFail {
		t.Errorf("expected fail, got %s", got)
	}
	if evidence.OverallStatus(checks) != evidence.StatusFail {
		t.Errorf("expected overall fail")
	}
}

func TestEvaluate_NotInstalled(t *testing.T) {
	checks := diagnostics.Evaluate(diagnostics.Signals{K3sHealth: k3s.HealthStatus{Healthy: true}})
	if got := statusOf(t, checks, "installed-state-present"); got != evidence.StatusFail {
		t.Errorf("expected fail, got %s", got)
	}
}

func TestEvaluate_CorruptInstalledState(t *testing.T) {
	checks := diagnostics.Evaluate(diagnostics.Signals{
		InstalledStateErr: errors.New("installed-state.json does not satisfy installed-state.v1"),
		K3sHealth:         k3s.HealthStatus{Healthy: true},
	})
	if got := statusOf(t, checks, "installed-state-valid"); got != evidence.StatusFail {
		t.Errorf("expected fail, got %s", got)
	}
}
