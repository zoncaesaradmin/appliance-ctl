package repair_test

import (
	"context"
	"errors"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/repair"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

func ownedState() *state.InstalledState {
	return &state.InstalledState{K3sOwnership: state.K3sOwnership{Owned: true, OwnerApplianceVersion: "2.4.0"}}
}

func TestRepair_RestartsStoppedOwnedService(t *testing.T) {
	var restarted bool
	ops := k3s.Ops{
		DetectService: func(string) (k3s.ServiceSignal, error) {
			return k3s.ServiceSignal{Detected: true, Active: false}, nil
		},
		Restart: func(string) error {
			restarted = true
			return nil
		},
	}

	checks, err := repair.Repair(context.Background(), ops, ownedState(), "k3s.service")
	if err != nil {
		t.Fatalf("expected repair to succeed, got: %v", err)
	}
	if !restarted {
		t.Error("expected k3s to be restarted")
	}
	if len(checks) != 1 || checks[0].Status != "pass" {
		t.Errorf("expected a single passing check, got %+v", checks)
	}
}

func TestRepair_NoOpWhenAlreadyActive(t *testing.T) {
	var restarted bool
	ops := k3s.Ops{
		DetectService: func(string) (k3s.ServiceSignal, error) {
			return k3s.ServiceSignal{Detected: true, Active: true}, nil
		},
		Restart: func(string) error {
			restarted = true
			return nil
		},
	}

	if _, err := repair.Repair(context.Background(), ops, ownedState(), "k3s.service"); err != nil {
		t.Fatalf("expected repair to succeed, got: %v", err)
	}
	if restarted {
		t.Error("expected no restart when k3s is already active")
	}
}

// Dependency failure: not just stopped but genuinely gone.
func TestRepair_FailsWhenServiceMissingEntirely(t *testing.T) {
	ops := k3s.Ops{
		DetectService: func(string) (k3s.ServiceSignal, error) {
			return k3s.ServiceSignal{Detected: false}, nil
		},
	}

	if _, err := repair.Repair(context.Background(), ops, ownedState(), "k3s.service"); err == nil {
		t.Error("expected repair to refuse when the service is missing entirely")
	}
}

func TestRepair_FailsWhenNotOwned(t *testing.T) {
	ops := k3s.Ops{}

	if _, err := repair.Repair(context.Background(), ops, nil, "k3s.service"); err == nil {
		t.Error("expected repair to refuse on a host with no recorded install")
	}
}

func TestRepair_RestartFailurePropagates(t *testing.T) {
	ops := k3s.Ops{
		DetectService: func(string) (k3s.ServiceSignal, error) {
			return k3s.ServiceSignal{Detected: true, Active: false}, nil
		},
		Restart: func(string) error {
			return errors.New("simulated restart failure")
		},
	}

	if _, err := repair.Repair(context.Background(), ops, ownedState(), "k3s.service"); err == nil {
		t.Error("expected the simulated restart failure to propagate")
	}
}
