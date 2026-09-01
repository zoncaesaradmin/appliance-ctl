package helm

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
)

// traefikTransferTimeout is the entrypoint responding timeout for large
// /api/v1/files uploads and downloads (appliance bundles). Keep aligned with
// control-plane FilesTransferTimeout / WriteTimeout (30m).
const traefikTransferTimeout = "30m"

const traefikHelmChartConfigPrefix = `apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: traefik
  namespace: kube-system
spec:
  valuesContent: |-
    # UI/host-agent live in ace-apps while the main IngressRoute stays with
    # controlplane in ace-system. Traefik must resolve cross-namespace Service
    # references on that IngressRoute.
    providers:
      kubernetesCRD:
        allowCrossNamespace: true
    ports:
`

const traefikWebPortTimeouts = `      web:
        transport:
          respondingTimeouts:
            readTimeout: ` + traefikTransferTimeout + `
            writeTimeout: ` + traefikTransferTimeout + `
            idleTimeout: ` + traefikTransferTimeout + `
`

const traefikWebPortPlaintextHTTP = `      web:
        redirectTo: null
        redirections: {}
        transport:
          respondingTimeouts:
            readTimeout: ` + traefikTransferTimeout + `
            writeTimeout: ` + traefikTransferTimeout + `
            idleTimeout: ` + traefikTransferTimeout + `
`

const traefikWebsecurePortTimeouts = `      websecure:
        transport:
          respondingTimeouts:
            readTimeout: ` + traefikTransferTimeout + `
            writeTimeout: ` + traefikTransferTimeout + `
            idleTimeout: ` + traefikTransferTimeout + `
`

func traefikHelmChartConfigManifest(plaintextHTTP bool) string {
	web := traefikWebPortTimeouts
	if plaintextHTTP {
		web = traefikWebPortPlaintextHTTP
	}
	return traefikHelmChartConfigPrefix + web + traefikWebsecurePortTimeouts
}

// EnsureTraefikTransferTimeouts applies a HelmChartConfig so K3s Traefik does
// not cut multi-GB /api/v1/files transfers with default entrypoint timeouts
// (client often sees curl HTTP/2 PROTOCOL_ERROR / 502) and can route
// IngressRoutes to Services outside the IngressRoute namespace (ui-server in
// ace-apps while the route lives in ace-system). When plaintextHTTP is true,
// Traefik must not redirect the web entrypoint away from application routes.
func EnsureTraefikTransferTimeouts(ctx context.Context, run cli.Runner, kubeconfig string, plaintextHTTP bool) (evidence.Check, error) {
	check := evidence.Check{
		ID:              "traefik-transfer-timeouts",
		Category:        "k3s",
		Timestamp:       time.Now().UTC(),
		Idempotent:      true,
		SecretsRedacted: true,
	}
	if run == nil {
		check.Status = evidence.StatusFail
		check.Message = "kubectl runner is nil"
		return check, fmt.Errorf("helm: traefik transfer timeouts: runner is nil")
	}

	tmp, err := os.CreateTemp("", "zon-traefik-timeouts-*.yaml")
	if err != nil {
		check.Status = evidence.StatusFail
		check.Message = err.Error()
		return check, fmt.Errorf("helm: traefik transfer timeouts: create temp: %w", err)
	}
	path := tmp.Name()
	defer func() { _ = os.Remove(path) }()
	if _, err := tmp.WriteString(traefikHelmChartConfigManifest(plaintextHTTP)); err != nil {
		_ = tmp.Close()
		check.Status = evidence.StatusFail
		check.Message = err.Error()
		return check, fmt.Errorf("helm: traefik transfer timeouts: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		check.Status = evidence.StatusFail
		check.Message = err.Error()
		return check, fmt.Errorf("helm: traefik transfer timeouts: close temp: %w", err)
	}

	if _, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", path); err != nil {
		check.Status = evidence.StatusFail
		check.Message = err.Error()
		return check, fmt.Errorf("helm: apply traefik transfer timeouts: %w", err)
	}
	check.Status = evidence.StatusPass
	check.Message = fmt.Sprintf("traefik entrypoint respondingTimeouts set to %s; allowCrossNamespace enabled", traefikTransferTimeout)
	if plaintextHTTP {
		check.Message += "; web entrypoint plaintext HTTP enabled"
	}
	return check, nil
}
