package bootstrapadmin

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
)

const chartName = "appliance-control-plane"

// Options describes the in-cluster first-admin bootstrap call zonctl runs
// after the chart rollout is ready.
type Options struct {
	Run           cli.InputRunner
	Kubeconfig    string
	Namespace     string
	ReleaseName   string
	AdminUsername string
	AdminPassword []byte
}

// Init creates the first administrator through the supported application
// bootstrap command already packaged into the control-plane container.
func Init(ctx context.Context, opts Options) (evidence.Check, error) {
	check := evidence.Check{
		ID:              "application-bootstrap-first-admin",
		Category:        "application",
		Timestamp:       time.Now().UTC(),
		Idempotent:      true,
		SecretsRedacted: true,
	}

	if opts.Run == nil {
		check.Status = evidence.StatusFail
		check.Message = "bootstrap runner is not configured"
		return check, fmt.Errorf("bootstrap: runner is not configured")
	}
	if strings.TrimSpace(opts.Kubeconfig) == "" || strings.TrimSpace(opts.Namespace) == "" || strings.TrimSpace(opts.ReleaseName) == "" {
		check.Status = evidence.StatusFail
		check.Message = "bootstrap requires kubeconfig, namespace, and release name"
		return check, fmt.Errorf("bootstrap: kubeconfig, namespace, and release name are required")
	}
	if strings.TrimSpace(opts.AdminUsername) == "" {
		check.Status = evidence.StatusFail
		check.Message = "bootstrap administrator username is empty"
		return check, fmt.Errorf("bootstrap: administrator username is required")
	}
	if len(opts.AdminPassword) == 0 {
		check.Status = evidence.StatusFail
		check.Message = "bootstrap administrator password is empty"
		return check, fmt.Errorf("bootstrap: administrator password is required")
	}

	deployment := fmt.Sprintf("deploy/%s-%s", opts.ReleaseName, chartName)
	args := []string{
		"--kubeconfig", opts.Kubeconfig,
		"--namespace", opts.Namespace,
		"exec", "-i", deployment, "--",
		"/appliance-server",
		"bootstrap", "init",
		"--admin-username", opts.AdminUsername,
		"--admin-password-file", "/dev/stdin",
	}
	out, err := opts.Run(ctx, opts.AdminPassword, "kubectl", args...)
	trimmed := strings.TrimSpace(out)
	if err != nil {
		msg := strings.ToLower(trimmed + "\n" + err.Error())
		if strings.Contains(msg, "already initialized") {
			check.Status = evidence.StatusPass
			check.Message = "appliance already initialized; first-admin bootstrap skipped"
			return check, nil
		}
		check.Status = evidence.StatusFail
		if trimmed == "" {
			trimmed = err.Error()
		}
		check.Message = trimmed
		return check, fmt.Errorf("bootstrap: initialize first administrator: %w", err)
	}

	check.Status = evidence.StatusPass
	if trimmed == "" {
		check.Message = fmt.Sprintf("created first administrator %q", opts.AdminUsername)
	} else {
		check.Message = trimmed
	}
	return check, nil
}
