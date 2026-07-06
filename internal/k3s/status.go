package k3s

import "fmt"

// HealthSignal is what was actually observed about a running K3s
// installation.
type HealthSignal struct {
	ServiceActive      bool
	APIServerReachable bool
	Version            string
	ExpectedVersion    string
}

// HealthStatus is the interpreted result, ready for the `status` and
// `verify` commands (and support bundles) to report.
type HealthStatus struct {
	Healthy bool
	Reasons []string
}

// EvaluateHealth turns raw signals into a healthy/unhealthy verdict with
// human-readable reasons. It is pure so it can be unit tested without a
// running K3s.
func EvaluateHealth(signal HealthSignal) HealthStatus {
	var reasons []string

	if !signal.ServiceActive {
		reasons = append(reasons, "k3s service is not active")
	}
	if !signal.APIServerReachable {
		reasons = append(reasons, "kubernetes API server is not reachable")
	}
	if signal.ExpectedVersion != "" && signal.Version != signal.ExpectedVersion {
		reasons = append(reasons, fmt.Sprintf("running version %q, expected %q", signal.Version, signal.ExpectedVersion))
	}

	return HealthStatus{Healthy: len(reasons) == 0, Reasons: reasons}
}
