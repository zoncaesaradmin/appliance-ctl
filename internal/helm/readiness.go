package helm

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
)

const (
	clusterReadyTimeout      = 2 * time.Minute
	clusterReadyPollInterval = 2 * time.Second
)

// EnsureClusterBaseline waits for the local K3s control plane and the
// bundle-declared chart dependencies to become usable before Helm apply.
// This avoids racing a freshly started K3s instance where containerd is
// up but the API server, node readiness, or storage provisioner are not
// yet ready for workload rollout.
func EnsureClusterBaseline(ctx context.Context, run cli.Runner, kubeconfig, valuesPath string) ([]evidence.Check, error) {
	values, err := loadChartValues(valuesPath)
	if err != nil {
		return nil, err
	}

	var checks []evidence.Check

	nodeCheck, err := waitNodesReady(ctx, run, kubeconfig)
	checks = append(checks, nodeCheck)
	if err != nil {
		return checks, err
	}

	// CoreDNS Ready is the practical signal that kube-proxy / CNI service
	// routing works after a K3s (re)start. Without this, a split-brain
	// leftover shim set can leave ClusterIP unreachable while the node
	// still reports Ready and helm --wait later times out on PVCs.
	corednsCheck, err := waitDeploymentAvailable(ctx, run, kubeconfig, "kube-system", "coredns", "k3s-coredns-ready")
	checks = append(checks, corednsCheck)
	if err != nil {
		return checks, err
	}

	if values.Persistence.Enabled && values.Persistence.StorageClassName != "" {
		storageCheck, err := waitStorageClassReady(ctx, run, kubeconfig, values.Persistence.StorageClassName)
		checks = append(checks, storageCheck)
		if err != nil {
			return checks, err
		}
		if values.Persistence.StorageClassName == "local-path" {
			provisionerCheck, err := waitDeploymentAvailable(ctx, run, kubeconfig, "kube-system", "local-path-provisioner", "k3s-local-path-provisioner-ready")
			checks = append(checks, provisionerCheck)
			if err != nil {
				return checks, err
			}
		}
	}

	return checks, nil
}

func waitNodesReady(ctx context.Context, run cli.Runner, kubeconfig string) (evidence.Check, error) {
	check := evidence.Check{
		ID:              "k3s-cluster-nodes-ready",
		Category:        "k3s",
		Timestamp:       time.Now().UTC(),
		Idempotent:      true,
		SecretsRedacted: true,
	}

	deadline := time.Now().Add(clusterReadyTimeout)
	var lastState string
	for {
		out, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "get", "nodes", "--no-headers")
		if err == nil {
			if ready, state := nodesReady(strings.TrimSpace(out)); ready {
				check.Status = evidence.StatusPass
				check.Message = state
				return check, nil
			} else if state != "" {
				lastState = state
			}
		} else if !isTransientKubeError(err) {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			return check, fmt.Errorf("helm: wait for ready cluster nodes: %w", err)
		} else {
			lastState = err.Error()
		}

		if time.Now().After(deadline) {
			if lastState == "" {
				lastState = "cluster nodes did not become Ready before timeout"
			}
			check.Status = evidence.StatusFail
			check.Message = lastState
			return check, fmt.Errorf("helm: wait for ready cluster nodes: %s", lastState)
		}
		if err := waitClusterRetry(ctx); err != nil {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			return check, err
		}
	}
}

func nodesReady(out string) (bool, string) {
	lines := strings.Split(out, "\n")
	readyNames := make([]string, 0, len(lines))
	pendingStates := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			pendingStates = append(pendingStates, line)
			continue
		}
		name := fields[0]
		status := fields[1]
		if strings.HasPrefix(status, "Ready") {
			readyNames = append(readyNames, name)
			continue
		}
		pendingStates = append(pendingStates, fmt.Sprintf("%s=%s", name, status))
	}
	if len(readyNames) == 0 && len(pendingStates) == 0 {
		return false, "cluster API is reachable but no nodes are registered yet"
	}
	if len(pendingStates) > 0 {
		return false, "waiting for Ready nodes: " + strings.Join(pendingStates, ", ")
	}
	return true, fmt.Sprintf("cluster nodes are Ready: %s", strings.Join(readyNames, ", "))
}

func waitStorageClassReady(ctx context.Context, run cli.Runner, kubeconfig, storageClass string) (evidence.Check, error) {
	check := evidence.Check{
		ID:              "k3s-storage-class-" + evidence.SanitizeIDSegment(storageClass),
		Category:        "storage",
		Timestamp:       time.Now().UTC(),
		Idempotent:      true,
		SecretsRedacted: true,
	}

	deadline := time.Now().Add(clusterReadyTimeout)
	var lastState string
	for {
		out, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "get", "storageclass", storageClass, "-o", "name")
		if err == nil {
			name := strings.TrimSpace(out)
			if name == "" {
				name = storageClass
			}
			check.Status = evidence.StatusPass
			check.Message = fmt.Sprintf("storage class %s is available", name)
			return check, nil
		}
		if !namespaceNotFound(err) && !isTransientKubeError(err) {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			return check, fmt.Errorf("helm: wait for storage class %s: %w", storageClass, err)
		}
		lastState = err.Error()
		if time.Now().After(deadline) {
			check.Status = evidence.StatusFail
			check.Message = lastState
			return check, fmt.Errorf("helm: wait for storage class %s: %s", storageClass, lastState)
		}
		if err := waitClusterRetry(ctx); err != nil {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			return check, err
		}
	}
}

func waitDeploymentAvailable(ctx context.Context, run cli.Runner, kubeconfig, namespace, deployment, checkID string) (evidence.Check, error) {
	check := evidence.Check{
		ID:              checkID,
		Category:        "k3s",
		Timestamp:       time.Now().UTC(),
		Idempotent:      true,
		SecretsRedacted: true,
	}

	deadline := time.Now().Add(clusterReadyTimeout)
	var lastState string
	for {
		out, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", namespace, "get", "deployment", deployment, "-o", "jsonpath={.status.availableReplicas}")
		if err == nil {
			value := strings.TrimSpace(out)
			if value == "" {
				lastState = fmt.Sprintf("%s/%s deployment exists but has no available replicas yet", namespace, deployment)
			} else if replicas, convErr := strconv.Atoi(value); convErr == nil && replicas > 0 {
				check.Status = evidence.StatusPass
				check.Message = fmt.Sprintf("%s/%s is available with %d replica(s)", namespace, deployment, replicas)
				return check, nil
			} else {
				lastState = fmt.Sprintf("%s/%s has %q available replicas", namespace, deployment, value)
			}
		} else if !namespaceNotFound(err) && !isTransientKubeError(err) {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			return check, fmt.Errorf("helm: wait for %s/%s: %w", namespace, deployment, err)
		} else {
			lastState = err.Error()
		}

		if time.Now().After(deadline) {
			check.Status = evidence.StatusFail
			check.Message = lastState
			return check, fmt.Errorf("helm: wait for %s/%s: %s", namespace, deployment, lastState)
		}
		if err := waitClusterRetry(ctx); err != nil {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			return check, err
		}
	}
}

func waitClusterRetry(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("helm: waiting for cluster readiness: %w", ctx.Err())
	case <-time.After(clusterReadyPollInterval):
		return nil
	}
}
