// Package helm applies the exact appliance Helm chart to the local K3s
// cluster with schema-validated values and waits for rollout.
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
