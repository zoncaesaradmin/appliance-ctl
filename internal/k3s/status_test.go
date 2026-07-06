package k3s_test

import (
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
)

func TestEvaluateHealth_AllGood(t *testing.T) {
	got := k3s.EvaluateHealth(k3s.HealthSignal{
		ServiceActive:      true,
		APIServerReachable: true,
		Version:            "v1.30.4+k3s1",
		ExpectedVersion:    "v1.30.4+k3s1",
	})
	if !got.Healthy {
		t.Errorf("expected healthy, got reasons: %v", got.Reasons)
	}
}

func TestEvaluateHealth_ReportsEachProblem(t *testing.T) {
	got := k3s.EvaluateHealth(k3s.HealthSignal{
		ServiceActive:      false,
		APIServerReachable: false,
		Version:            "v1.29.0+k3s1",
		ExpectedVersion:    "v1.30.4+k3s1",
	})
	if got.Healthy {
		t.Fatal("expected unhealthy")
	}
	if len(got.Reasons) != 3 {
		t.Errorf("expected 3 reasons, got %d: %v", len(got.Reasons), got.Reasons)
	}
}

func TestEvaluateHealth_VersionCheckSkippedWhenNoExpectation(t *testing.T) {
	got := k3s.EvaluateHealth(k3s.HealthSignal{
		ServiceActive:      true,
		APIServerReachable: true,
		Version:            "v1.30.4+k3s1",
	})
	if !got.Healthy {
		t.Errorf("expected healthy when no expected version is set, got: %v", got.Reasons)
	}
}
