// Package helm applies the bundled Argo CRDs and the exact appliance
// Helm chart to the local K3s cluster: "Apply the bundled versioned Argo
// CRDs before the chart" and "Install the exact Helm chart with
// schema-validated values and wait for rollout" (docs/release-plan.md
// Fresh Install Sequence).
package helm

import "github.com/zoncaesaradmin/appliance-ctl/internal/cli"

// Applier shells out to the bundled kubectl and helm binaries against a
// single kubeconfig (always the local K3s API server; never a remote
// cluster).
type Applier struct {
	Run        cli.Runner
	Kubeconfig string
}

// NewApplier returns an Applier using the real kubectl/helm binaries.
// Pass a fake cli.Runner in tests instead of constructing this directly.
func NewApplier(kubeconfig string) *Applier {
	return &Applier{Run: cli.Exec, Kubeconfig: kubeconfig}
}
