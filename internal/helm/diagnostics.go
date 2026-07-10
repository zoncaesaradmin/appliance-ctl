package helm

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
)

const (
	maxDiagnosticMessageBytes = 4000
	diagnosticRemediation     = "Inspect the captured Helm and Kubernetes diagnostic output for the blocking workload condition, resolve it on the target cluster, and rerun zonctl install or zonctl upgrade."
)

// CollectFailureDiagnostics captures high-signal release state before a
// rollback tears it down, so a failed install/upgrade returns actionable
// cluster context instead of only Helm's generic timeout text.
func CollectFailureDiagnostics(ctx context.Context, run cli.Runner, kubeconfig string, rel ChartRelease) []evidence.Check {
	type command struct {
		idSuffix string
		category string
		args     []string
	}

	commands := []command{
		{
			idSuffix: "helm-status",
			category: "chart",
			args:     []string{"--kubeconfig", kubeconfig, "status", rel.Name, "--namespace", rel.Namespace},
		},
		{
			idSuffix: "resources",
			category: "chart",
			args:     []string{"--kubeconfig", kubeconfig, "--namespace", rel.Namespace, "get", "pods,svc,pvc", "-o", "wide"},
		},
		{
			idSuffix: "events",
			category: "chart",
			args:     []string{"--kubeconfig", kubeconfig, "--namespace", rel.Namespace, "get", "events", "--sort-by=.lastTimestamp"},
		},
	}

	checks := make([]evidence.Check, 0, len(commands))
	for _, cmd := range commands {
		name := "kubectl"
		if cmd.idSuffix == "helm-status" {
			name = "helm"
		}
		out, err := run(ctx, name, cmd.args...)
		msg := strings.TrimSpace(out)
		if err != nil {
			if msg == "" {
				msg = err.Error()
			} else {
				msg = fmt.Sprintf("%s\n%s", msg, err)
			}
		}
		if msg == "" {
			msg = "no output"
		}
		checks = append(checks, evidence.Check{
			ID:              "helm-release-" + evidence.SanitizeIDSegment(rel.Name) + "-" + cmd.idSuffix,
			Category:        cmd.category,
			Status:          evidence.StatusOperatorAction,
			Message:         truncateDiagnostic(msg),
			Remediation:     diagnosticRemediation,
			Timestamp:       time.Now().UTC(),
			Idempotent:      true,
			SecretsRedacted: true,
		})
	}
	return checks
}

func truncateDiagnostic(msg string) string {
	if len(msg) <= maxDiagnosticMessageBytes {
		return msg
	}
	return msg[:maxDiagnosticMessageBytes] + "\n... output truncated ..."
}
