package diagnostics_test

import (
	"errors"
	"testing"
	"time"

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

// This is the exact scenario that motivated adding chart/ingress checks:
// installed-state is present and K3s is healthy, but the chart's
// IngressRoute was never created, so no traffic reaches the appliance
// pod. Before this check existed, Evaluate would have reported overall
// pass here.
func TestEvaluate_HealthyInstallButNoIngressRoute(t *testing.T) {
	checks := diagnostics.Evaluate(diagnostics.Signals{
		InstalledState: &state.InstalledState{InstalledVersion: "2.4.0"},
		K3sHealth:      k3s.HealthStatus{Healthy: true},
		ChartHealth:    diagnostics.ChartHealth{Checked: true, Healthy: true, Message: "release zon is deployed"},
		IngressHealth:  diagnostics.IngressHealth{Checked: true, Present: false, Message: "no ingress route found in namespace zon"},
	})
	if got := statusOf(t, checks, "chart-release-health"); got != evidence.StatusPass {
		t.Errorf("expected chart-release-health pass, got %s", got)
	}
	if got := statusOf(t, checks, "ingress-route-present"); got != evidence.StatusFail {
		t.Errorf("expected ingress-route-present fail, got %s", got)
	}
	if evidence.OverallStatus(checks) != evidence.StatusFail {
		t.Errorf("expected overall fail when no ingress route exists")
	}
}

func TestEvaluate_ChartUnhealthy(t *testing.T) {
	checks := diagnostics.Evaluate(diagnostics.Signals{
		InstalledState: &state.InstalledState{InstalledVersion: "2.4.0"},
		K3sHealth:      k3s.HealthStatus{Healthy: true},
		ChartHealth:    diagnostics.ChartHealth{Checked: true, Healthy: false, Message: `release zon status is "failed", want "deployed"`},
	})
	if got := statusOf(t, checks, "chart-release-health"); got != evidence.StatusFail {
		t.Errorf("expected fail, got %s", got)
	}
	if evidence.OverallStatus(checks) != evidence.StatusFail {
		t.Errorf("expected overall fail")
	}
}

// When chart/ingress were never checked (e.g. the appliance is not
// installed, or K3s is down), Evaluate must not emit misleading
// chart/ingress findings on top of the real cause.
// A schema category enum violation once broke the whole evidence report
// (see bootstrapadmin's equivalent test), so the new chart/ingress
// checks are verified against the real evidence.v1 schema validator, not
// just a compile check.
func TestEvaluate_ChartAndIngressChecksSatisfyEvidenceSchema(t *testing.T) {
	checks := diagnostics.Evaluate(diagnostics.Signals{
		InstalledState: &state.InstalledState{InstalledVersion: "2.4.0"},
		K3sHealth:      k3s.HealthStatus{Healthy: true},
		ChartHealth:    diagnostics.ChartHealth{Checked: true, Healthy: true, Message: "release zon is deployed"},
		IngressHealth:  diagnostics.IngressHealth{Checked: true, Present: false, Message: "no ingress route found in namespace zon"},
	})
	if _, err := evidence.BuildReport("status", "2.4.0", "evidence-test", checks, time.Now()); err != nil {
		t.Fatalf("BuildReport rejected checks with real schema validation: %v", err)
	}
}

func TestEvaluate_SkipsChartAndIngressWhenNotChecked(t *testing.T) {
	checks := diagnostics.Evaluate(diagnostics.Signals{K3sHealth: k3s.HealthStatus{Healthy: false, Reasons: []string{"k3s service is not active"}}})
	for _, id := range []string{"chart-release-health", "ingress-route-present"} {
		for _, c := range checks {
			if c.ID == id {
				t.Errorf("expected no %q check when not checked, found one with status %s", id, c.Status)
			}
		}
	}
}
