package helm

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
)

const (
	namespaceReadyTimeout      = 60 * time.Second
	namespaceReadyPollInterval = 1 * time.Second
)

// EnsureNamespace makes sure namespace exists and is usable before any
// chart prerequisite or Helm apply step touches it. A namespace stuck in
// Terminating from a previous failed/unwound install is waited out for a
// bounded period so an immediate rerun can self-heal once deletion
// finishes, instead of failing later with an opaque "forbidden: namespace
// is being terminated" error while creating a secret or chart object.
// When labels is non-empty they are applied (and overwritten) so PSA
// exceptions such as privileged for hostNetwork DNS land before pods.
func EnsureNamespace(ctx context.Context, run cli.Runner, kubeconfig, namespace string, labels map[string]string) error {
	if namespace == "" {
		return fmt.Errorf("helm: namespace must not be empty")
	}

	deadline := time.Now().Add(namespaceReadyTimeout)
	for {
		phase, found, retryable, err := namespacePhase(ctx, run, kubeconfig, namespace)
		if err != nil {
			if !retryable || time.Now().After(deadline) {
				return err
			}
			if err := waitNamespaceRetry(ctx); err != nil {
				return err
			}
			continue
		}
		if !found {
			if err := createNamespace(ctx, run, kubeconfig, namespace); err == nil || namespaceAlreadyExists(err) {
				return applyNamespaceLabels(ctx, run, kubeconfig, namespace, labels)
			} else if (namespaceTerminating(err) || isTransientKubeError(err)) && time.Now().Before(deadline) {
				if err := waitNamespaceRetry(ctx); err != nil {
					return err
				}
				continue
			} else {
				return err
			}
		}
		if phase != "Terminating" {
			return applyNamespaceLabels(ctx, run, kubeconfig, namespace, labels)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("helm: namespace %s is still terminating from a previous run; wait for deletion to finish or clear finalizers before retrying", namespace)
		}
		if err := waitNamespaceRetry(ctx); err != nil {
			return err
		}
	}
}

func applyNamespaceLabels(ctx context.Context, run cli.Runner, kubeconfig, namespace string, labels map[string]string) error {
	if len(labels) == 0 {
		return nil
	}
	args := []string{"--kubeconfig", kubeconfig, "label", "namespace", namespace, "--overwrite"}
	for key, value := range labels {
		args = append(args, key+"="+value)
	}
	if _, err := run(ctx, "kubectl", args...); err != nil {
		return fmt.Errorf("helm: label namespace %s: %w", namespace, err)
	}
	return nil
}

func namespacePhase(ctx context.Context, run cli.Runner, kubeconfig, namespace string) (phase string, found bool, retryable bool, err error) {
	out, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "get", "namespace", namespace, "-o", "jsonpath={.status.phase}")
	if err != nil {
		if namespaceNotFound(err) {
			return "", false, false, nil
		}
		return "", false, isTransientKubeError(err), fmt.Errorf("helm: get namespace %s: %w", namespace, err)
	}
	phase = strings.TrimSpace(out)
	if phase == "" {
		phase = "Active"
	}
	return phase, true, false, nil
}

func createNamespace(ctx context.Context, run cli.Runner, kubeconfig, namespace string) error {
	if _, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "create", "namespace", namespace); err != nil {
		return fmt.Errorf("helm: ensure namespace %s: %w", namespace, err)
	}
	return nil
}

func namespaceNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "notfound") || strings.Contains(msg, "not found")
}

func namespaceAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "alreadyexists") || strings.Contains(msg, "already exists")
}

func namespaceTerminating(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "being terminated") || strings.Contains(msg, "terminating")
}

func isTransientKubeError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "the server was unable to return a response") ||
		strings.Contains(msg, "currently unable to handle the request") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "tls handshake timeout") ||
		strings.Contains(msg, "eof") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "no route to host")
}

func waitNamespaceRetry(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("helm: waiting for namespace readiness: %w", ctx.Err())
	case <-time.After(namespaceReadyPollInterval):
		return nil
	}
}
