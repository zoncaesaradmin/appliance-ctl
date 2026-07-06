package k3s

import (
	"fmt"
	"strings"

	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

// ServiceSignal is what the host currently shows about a K3s service and
// cluster, independent of what installed-state (the ownership record)
// says. Healthy, RunningVersion, and ForeignNamespaces are only
// meaningful when Active is true; DetectService alone cannot populate
// them (see InspectCluster).
type ServiceSignal struct {
	Detected bool // a k3s systemd unit/service exists on the host at all
	Active   bool // it is currently running

	// Healthy reports whether the cluster's node(s) are Ready. Zero value
	// (false) is the safe default when it could not be determined.
	Healthy bool
	// RunningVersion is the K3s version currently installed, if known.
	RunningVersion string
	// ForeignNamespaces lists namespaces carrying workloads this
	// appliance did not create (excludes kube-system, kube-public,
	// kube-node-lease, and the appliance's own namespace).
	ForeignNamespaces []string
}

// Decision is the outcome of reconciling installed-state against the
// host's actual K3s service signal.
type Decision string

const (
	// DecisionFreshInstall: no installed-state, no existing service.
	// Proceed with a normal fresh install.
	DecisionFreshInstall Decision = "fresh-install"

	// DecisionReuseOwned: installed-state records this exact appliance
	// version as the owner. Ensure the service is running (this is the
	// path a plain restart takes: service present but possibly stopped).
	DecisionReuseOwned Decision = "reuse-owned"

	// DecisionUpgradeOwned: installed-state records ownership by a
	// different (presumably older) appliance version. The upgrade path
	// applies, not a fresh install.
	DecisionUpgradeOwned Decision = "upgrade-owned"

	// DecisionRequiresRepair: installed-state records an owned
	// installation, but no matching service was found on the host. Data
	// may still exist; this is a repair scenario, not a fresh install.
	DecisionRequiresRepair Decision = "requires-repair"

	// DecisionRejectUnrecordedExistingService: no installed-state, but a
	// K3s service exists and this host has a prior (crashed) install
	// attempt on record. Installing fresh now would conflict with
	// leftover state; repair must run first.
	DecisionRejectUnrecordedExistingService Decision = "reject-unrecorded-existing-service"

	// DecisionAdoptExisting: no installed-state, an existing K3s service
	// is present, this host has no prior install attempt on record, and
	// the cluster is either obviously safe to adopt (healthy, no foreign
	// workloads) or the operator explicitly forced adoption. K3s is
	// upgraded to the target version if required, and installation
	// proceeds against the adopted cluster.
	DecisionAdoptExisting Decision = "adopt-existing-cluster"

	// DecisionRequiresForceAdopt: an existing, unrecorded K3s cluster was
	// found that is not obviously safe to adopt (unhealthy, and/or
	// carrying foreign workloads). Per "do not silently modify" an
	// unrelated cluster, adoption is refused until the operator passes an
	// explicit force-adopt override.
	DecisionRequiresForceAdopt Decision = "requires-force-adopt"
)

// DecideOwnership reconciles the on-host installed-state record (nil on a
// fresh host) with the K3s service/cluster actually observed on the
// host. priorInstallAttempted should be derived from the transaction
// journal: whether this host has ever begun an install, regardless of
// outcome. It disambiguates a leftover service from a crashed install
// (repair needed) versus a genuinely pre-existing cluster (adopt or
// require force-adopt). forceAdopt is the operator's explicit override
// for a cluster that isn't obviously safe to adopt.
func DecideOwnership(applianceVersion string, installed *state.InstalledState, signal ServiceSignal, priorInstallAttempted, forceAdopt bool) (Decision, string) {
	if installed != nil {
		if !installed.K3sOwnership.Owned {
			return DecisionRequiresForceAdopt, "installed-state does not record appliance ownership of K3s"
		}
		if !signal.Detected {
			return DecisionRequiresRepair, "installed-state records an owned K3s installation, but no K3s service was found on the host"
		}
		if installed.K3sOwnership.OwnerApplianceVersion != applianceVersion {
			return DecisionUpgradeOwned, fmt.Sprintf("K3s is owned by appliance version %s; the upgrade path applies", installed.K3sOwnership.OwnerApplianceVersion)
		}
		return DecisionReuseOwned, fmt.Sprintf("K3s is already owned by appliance version %s", applianceVersion)
	}

	if !signal.Detected {
		return DecisionFreshInstall, "no existing K3s detected; proceeding with a fresh install"
	}
	if priorInstallAttempted {
		return DecisionRejectUnrecordedExistingService, "a K3s service exists but no installed-state was ever recorded for it; run 'zonctl repair' before installing"
	}

	safeToAdopt := signal.Healthy && len(signal.ForeignNamespaces) == 0
	if safeToAdopt {
		return DecisionAdoptExisting, "existing K3s cluster is healthy and carries no foreign workloads; adopting it"
	}
	if forceAdopt {
		return DecisionAdoptExisting, fmt.Sprintf("adopting existing K3s cluster by explicit override (healthy=%t, foreign workloads: %s)", signal.Healthy, strings.Join(signal.ForeignNamespaces, ", "))
	}

	var reasons []string
	if !signal.Healthy {
		reasons = append(reasons, "cluster health could not be confirmed")
	}
	if len(signal.ForeignNamespaces) > 0 {
		reasons = append(reasons, fmt.Sprintf("foreign workloads present in namespace(s): %s", strings.Join(signal.ForeignNamespaces, ", ")))
	}
	return DecisionRequiresForceAdopt, fmt.Sprintf("an existing K3s cluster was found that this appliance never installed (%s); pass an explicit force-adopt override to take ownership", strings.Join(reasons, "; "))
}
