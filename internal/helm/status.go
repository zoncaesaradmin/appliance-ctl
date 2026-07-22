package helm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
)

// CheckReleaseHealth reports whether releaseName is present in namespace
// and in Helm's "deployed" status. It never returns an error for a
// missing/unhealthy release — that is a legitimate, reportable outcome
// for status/verify — only for a Helm invocation that itself failed
// (binary missing, kubeconfig unreachable, malformed output).
func CheckReleaseHealth(ctx context.Context, run cli.Runner, kubeconfig, releaseName, namespace string) (healthy bool, message string, err error) {
	out, runErr := run(ctx, "helm", "--kubeconfig", kubeconfig, "status", releaseName, "--namespace", namespace, "-o", "json")
	if runErr != nil {
		if helmReleaseMissing(runErr) {
			return false, fmt.Sprintf("release %s not found in namespace %s", releaseName, namespace), nil
		}
		return false, "", fmt.Errorf("helm: status %s: %w", releaseName, runErr)
	}

	var parsed struct {
		Info struct {
			Status string `json:"status"`
		} `json:"info"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		return false, "", fmt.Errorf("helm: parse status output for %s: %w", releaseName, err)
	}

	status := strings.ToLower(parsed.Info.Status)
	if status != "deployed" {
		return false, fmt.Sprintf("release %s status is %q, want \"deployed\"", releaseName, parsed.Info.Status), nil
	}
	return true, fmt.Sprintf("release %s is deployed", releaseName), nil
}

// CheckPVCBound reports registry storage readiness without reading any blob
// content. It is safe for status, verify, and support-bundle diagnostics.
func CheckPVCBound(ctx context.Context, run cli.Runner, kubeconfig, namespace, pvcName string) (bool, string, error) {
	out, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", namespace,
		"get", "pvc", pvcName, "-o", "jsonpath={.status.phase}")
	if err != nil {
		return false, "", fmt.Errorf("helm: inspect pvc %s/%s: %w", namespace, pvcName, err)
	}
	phase := strings.TrimSpace(out)
	if phase != "Bound" {
		return false, fmt.Sprintf("pvc %s/%s phase is %q, want Bound", namespace, pvcName, phase), nil
	}
	return true, fmt.Sprintf("pvc %s/%s is Bound", namespace, pvcName), nil
}
