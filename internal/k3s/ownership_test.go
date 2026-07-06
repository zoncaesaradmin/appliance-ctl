package k3s_test

import (
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

func ownedState(ownerVersion string) *state.InstalledState {
	return &state.InstalledState{
		K3sOwnership: state.K3sOwnership{Owned: true, OwnerApplianceVersion: ownerVersion},
	}
}

// Fresh host: no installed-state, nothing running.
func TestDecideOwnership_FreshHost(t *testing.T) {
	decision, _ := k3s.DecideOwnership("2.4.0", nil, k3s.ServiceSignal{Detected: false}, false, false)
	if decision != k3s.DecisionFreshInstall {
		t.Errorf("expected fresh-install, got %s", decision)
	}
}

// Restart: installed-state already owned by this exact version; the
// service may be stopped (e.g. after a host reboot) or running — either
// way the answer is "reuse it," not "install again."
func TestDecideOwnership_Restart(t *testing.T) {
	for _, active := range []bool{true, false} {
		decision, _ := k3s.DecideOwnership("2.4.0", ownedState("2.4.0"), k3s.ServiceSignal{Detected: true, Active: active}, false, false)
		if decision != k3s.DecisionReuseOwned {
			t.Errorf("active=%v: expected reuse-owned, got %s", active, decision)
		}
	}
}

// Interrupted install: no installed-state was ever recorded, but a K3s
// service exists and the journal shows this host has a prior install
// attempt on record (i.e. a crash happened after the service was created
// but before installed-state was written). This must not be treated as
// an adoptable cluster even if it happens to look healthy.
func TestDecideOwnership_InterruptedInstall(t *testing.T) {
	decision, reason := k3s.DecideOwnership("2.4.0", nil, k3s.ServiceSignal{Detected: true, Active: true, Healthy: true}, true, false)
	if decision != k3s.DecisionRejectUnrecordedExistingService {
		t.Errorf("expected reject-unrecorded-existing-service, got %s", decision)
	}
	if reason == "" {
		t.Error("expected a non-empty explanation directing the operator to repair")
	}
}

// Adoption: an existing K3s cluster this appliance never installed, but
// which is healthy and carries no foreign workloads, is safe to adopt
// automatically — no force flag needed.
func TestDecideOwnership_AutoAdoptsSafeCluster(t *testing.T) {
	signal := k3s.ServiceSignal{Detected: true, Active: true, Healthy: true, ForeignNamespaces: nil}
	decision, reason := k3s.DecideOwnership("2.4.0", nil, signal, false, false)
	if decision != k3s.DecisionAdoptExisting {
		t.Errorf("expected adopt-existing-cluster, got %s", decision)
	}
	if reason == "" {
		t.Error("expected a non-empty explanation")
	}
}

// An existing cluster carrying foreign workloads must not be silently
// adopted; it requires an explicit force-adopt override.
func TestDecideOwnership_RequiresForceAdoptWithForeignWorkloads(t *testing.T) {
	signal := k3s.ServiceSignal{Detected: true, Active: true, Healthy: true, ForeignNamespaces: []string{"customer-app"}}

	decision, _ := k3s.DecideOwnership("2.4.0", nil, signal, false, false)
	if decision != k3s.DecisionRequiresForceAdopt {
		t.Errorf("expected requires-force-adopt without override, got %s", decision)
	}

	decision, _ = k3s.DecideOwnership("2.4.0", nil, signal, false, true)
	if decision != k3s.DecisionAdoptExisting {
		t.Errorf("expected adopt-existing-cluster with force override, got %s", decision)
	}
}

// An unhealthy cluster (couldn't confirm node readiness) is likewise not
// obviously safe and needs the same override.
func TestDecideOwnership_RequiresForceAdoptWhenUnhealthy(t *testing.T) {
	signal := k3s.ServiceSignal{Detected: true, Active: true, Healthy: false}

	decision, _ := k3s.DecideOwnership("2.4.0", nil, signal, false, false)
	if decision != k3s.DecisionRequiresForceAdopt {
		t.Errorf("expected requires-force-adopt, got %s", decision)
	}

	decision, _ = k3s.DecideOwnership("2.4.0", nil, signal, false, true)
	if decision != k3s.DecisionAdoptExisting {
		t.Errorf("expected adopt-existing-cluster with force override, got %s", decision)
	}
}

func TestDecideOwnership_UpgradePath(t *testing.T) {
	decision, _ := k3s.DecideOwnership("2.5.0", ownedState("2.4.0"), k3s.ServiceSignal{Detected: true, Active: true}, false, false)
	if decision != k3s.DecisionUpgradeOwned {
		t.Errorf("expected upgrade-owned, got %s", decision)
	}
}

func TestDecideOwnership_RequiresRepairWhenServiceMissingDespiteOwnership(t *testing.T) {
	decision, _ := k3s.DecideOwnership("2.4.0", ownedState("2.4.0"), k3s.ServiceSignal{Detected: false}, false, false)
	if decision != k3s.DecisionRequiresRepair {
		t.Errorf("expected requires-repair, got %s", decision)
	}
}

func TestDecideOwnership_UnownedRecordRequiresForceAdopt(t *testing.T) {
	unowned := &state.InstalledState{K3sOwnership: state.K3sOwnership{Owned: false}}
	decision, _ := k3s.DecideOwnership("2.4.0", unowned, k3s.ServiceSignal{Detected: true}, false, false)
	if decision != k3s.DecisionRequiresForceAdopt {
		t.Errorf("expected requires-force-adopt, got %s", decision)
	}
}
