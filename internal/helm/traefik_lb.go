package helm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostagent"
)

const (
	traefikServiceNamespace = "kube-system"
	traefikServiceName      = "traefik"

	traefikLBReadyTimeout      = 2 * time.Minute
	traefikLBReadyPollInterval = 2 * time.Second
)

// EnsureTraefikManagementExternalIPs adds fixed management addresses (the
// WiFi AP control plane IP https://10.42.0.1/) to the K3s Traefik LoadBalancer
// Service as externalIPs.
//
// K3s ServiceLB only advertises the node's primary ethernet address as the
// Traefik VIP. Without an externalIP for the AP address, packets to
// 10.42.0.1:443 fall through to leftover CNI hostPort DNAT rules and never
// reach the UI—even when hostapd is up and phones can associate.
func EnsureTraefikManagementExternalIPs(ctx context.Context, run cli.Runner, kubeconfig string, extraIPs ...string) (evidence.Check, error) {
	check := evidence.Check{
		ID:              "traefik-management-external-ips",
		Category:        "k3s",
		Timestamp:       time.Now().UTC(),
		Idempotent:      true,
		SecretsRedacted: true,
	}
	if run == nil {
		check.Status = evidence.StatusFail
		check.Message = "kubectl runner is nil"
		return check, fmt.Errorf("helm: traefik management external IPs: runner is nil")
	}

	want := uniqueIPs(append([]string{hostagent.WifiAPManagementAddress}, extraIPs...))
	if len(want) == 0 {
		check.Status = evidence.StatusPass
		check.Message = "no management external IPs required"
		return check, nil
	}

	deadline := time.Now().Add(traefikLBReadyTimeout)
	var lastErr error
	for {
		current, err := traefikExternalIPs(ctx, run, kubeconfig)
		if err != nil {
			lastErr = err
		} else {
			merged := uniqueIPs(append(current, want...))
			if sameStringSet(current, merged) {
				check.Status = evidence.StatusPass
				check.Message = fmt.Sprintf("traefik externalIPs already include %s", strings.Join(want, ", "))
				return check, nil
			}
			if err := patchTraefikExternalIPs(ctx, run, kubeconfig, merged); err != nil {
				lastErr = err
			} else {
				check.Status = evidence.StatusPass
				check.Message = fmt.Sprintf("traefik externalIPs set to %s", strings.Join(merged, ", "))
				return check, nil
			}
		}
		if time.Now().After(deadline) {
			if lastErr == nil {
				lastErr = fmt.Errorf("timed out waiting for traefik service")
			}
			check.Status = evidence.StatusFail
			check.Message = lastErr.Error()
			return check, fmt.Errorf("helm: ensure traefik management external IPs: %w", lastErr)
		}
		select {
		case <-ctx.Done():
			check.Status = evidence.StatusFail
			check.Message = ctx.Err().Error()
			return check, ctx.Err()
		case <-time.After(traefikLBReadyPollInterval):
		}
	}
}

func traefikExternalIPs(ctx context.Context, run cli.Runner, kubeconfig string) ([]string, error) {
	out, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", traefikServiceNamespace,
		"get", "svc", traefikServiceName, "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("get traefik service: %w", err)
	}
	var doc struct {
		Spec struct {
			ExternalIPs []string `json:"externalIPs"`
		} `json:"spec"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, fmt.Errorf("parse traefik service: %w", err)
	}
	return doc.Spec.ExternalIPs, nil
}

func patchTraefikExternalIPs(ctx context.Context, run cli.Runner, kubeconfig string, ips []string) error {
	payload, err := json.Marshal(map[string]any{
		"spec": map[string]any{
			"externalIPs": ips,
		},
	})
	if err != nil {
		return err
	}
	_, err = run(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", traefikServiceNamespace,
		"patch", "svc", traefikServiceName, "--type=merge", "-p", string(payload))
	if err != nil {
		return fmt.Errorf("patch traefik externalIPs: %w", err)
	}
	return nil
}

func uniqueIPs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		ip := strings.TrimSpace(raw)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, v := range a {
		counts[v]++
	}
	for _, v := range b {
		if counts[v] == 0 {
			return false
		}
		counts[v]--
	}
	return true
}
