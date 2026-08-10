package helm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
)

// ImagePullSecretName is the installer-managed dockerconfig secret mirrored
// into every appliance product namespace (not kube-system or other K3s system
// namespaces). K3s registries.yaml remains the node-global pull path; this
// secret is the namespaced complement so any Deployment (including day-2
// image edits with imagePullPolicy Always) can authenticate to the lab LAN
// registry after the multi-namespace split.
const ImagePullSecretName = "appliance-image-pull"

// EnsureImagePullSecrets creates (or replaces) a dockerconfigjson Secret from
// cfg in each target namespace, and attaches it to every ServiceAccount in
// that namespace (default SA and controller SAs such as workflow-controller).
// Call again after Helm charts that create new SAs so those accounts inherit
// the pull secret.
func EnsureImagePullSecrets(ctx context.Context, run cli.Runner, kubeconfig string, cfg k3s.RegistriesConfig, namespaces ...string) (PreparedRelease, error) {
	prepared := PreparedRelease{}
	check := evidence.Check{
		ID:              "chart-prereq-image-pull-secret",
		Category:        "chart",
		Timestamp:       time.Now().UTC(),
		Idempotent:      true,
		SecretsRedacted: true,
	}

	if strings.TrimSpace(cfg.Registry) == "" {
		check.Status = evidence.StatusSkipped
		check.Message = "image-pull registry not configured; skip dockerconfig secrets"
		prepared.Checks = append(prepared.Checks, check)
		return prepared, nil
	}
	if err := cfg.Validate(); err != nil {
		check.Status, check.Message = evidence.StatusFail, err.Error()
		prepared.Checks = append(prepared.Checks, check)
		return prepared, fmt.Errorf("helm: image pull registry: %w", err)
	}

	namespaces = uniqueNonEmpty(namespaces)
	if len(namespaces) == 0 {
		check.Status = evidence.StatusSkipped
		check.Message = "no namespaces requested for image-pull secret"
		prepared.Checks = append(prepared.Checks, check)
		return prepared, nil
	}

	dockerConfigJSON, err := dockerConfigJSON(cfg)
	if err != nil {
		check.Status, check.Message = evidence.StatusFail, err.Error()
		prepared.Checks = append(prepared.Checks, check)
		return prepared, err
	}

	tempDir, err := os.MkdirTemp("", "appliance-image-pull-*")
	if err != nil {
		check.Status, check.Message = evidence.StatusFail, err.Error()
		prepared.Checks = append(prepared.Checks, check)
		return prepared, fmt.Errorf("helm: create temp dir for image-pull secret: %w", err)
	}
	defer os.RemoveAll(tempDir)
	configPath := filepath.Join(tempDir, ".dockerconfigjson")
	if err := os.WriteFile(configPath, dockerConfigJSON, 0o600); err != nil {
		check.Status, check.Message = evidence.StatusFail, err.Error()
		prepared.Checks = append(prepared.Checks, check)
		return prepared, fmt.Errorf("helm: write dockerconfigjson: %w", err)
	}

	applied := make([]string, 0, len(namespaces))
	for _, ns := range namespaces {
		if err := EnsureNamespace(ctx, run, kubeconfig, ns, nil); err != nil {
			check.Status, check.Message = evidence.StatusFail, err.Error()
			prepared.Checks = append(prepared.Checks, check)
			return prepared, err
		}
		if _, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", ns,
			"delete", "secret", ImagePullSecretName, "--ignore-not-found"); err != nil {
			check.Status, check.Message = evidence.StatusFail, err.Error()
			prepared.Checks = append(prepared.Checks, check)
			return prepared, fmt.Errorf("helm: replace image-pull secret in %s: %w", ns, err)
		}
		if _, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", ns,
			"create", "secret", "generic", ImagePullSecretName,
			"--type=kubernetes.io/dockerconfigjson",
			"--from-file=.dockerconfigjson="+configPath); err != nil {
			check.Status, check.Message = evidence.StatusFail, err.Error()
			prepared.Checks = append(prepared.Checks, check)
			return prepared, fmt.Errorf("helm: create image-pull secret in %s: %w", ns, err)
		}
		if err := ensureNamespaceServiceAccountsImagePullSecret(ctx, run, kubeconfig, ns); err != nil {
			check.Status, check.Message = evidence.StatusFail, err.Error()
			prepared.Checks = append(prepared.Checks, check)
			return prepared, err
		}
		applied = append(applied, ns)
		rollbackNS := ns
		prepared.cleanups = append(prepared.cleanups, func() error {
			return deleteSecret(ctx, run, kubeconfig, rollbackNS, ImagePullSecretName)
		})
	}

	check.Status = evidence.StatusPass
	check.Message = fmt.Sprintf("image-pull secret %s present in %s", ImagePullSecretName, strings.Join(applied, ", "))
	prepared.Checks = append(prepared.Checks, check)
	return prepared, nil
}

func dockerConfigJSON(cfg k3s.RegistriesConfig) ([]byte, error) {
	auth := base64.StdEncoding.EncodeToString([]byte(cfg.Username + ":" + cfg.Password))
	hosts := []string{cfg.Registry, "https://" + cfg.Registry}
	auths := map[string]map[string]string{}
	for _, host := range hosts {
		auths[host] = map[string]string{
			"username": cfg.Username,
			"password": cfg.Password,
			"auth":     auth,
		}
	}
	return json.Marshal(map[string]any{"auths": auths})
}

func ensureNamespaceServiceAccountsImagePullSecret(ctx context.Context, run cli.Runner, kubeconfig, namespace string) error {
	// Ensure at least the default SA exists before listing.
	if _, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", namespace,
		"get", "serviceaccount", "default"); err != nil {
		if _, createErr := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", namespace,
			"create", "serviceaccount", "default"); createErr != nil && !strings.Contains(strings.ToLower(createErr.Error()), "already") {
			return fmt.Errorf("helm: ensure default serviceaccount in %s: %w", namespace, createErr)
		}
	}
	out, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", namespace,
		"get", "serviceaccount", "-o", "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}")
	if err != nil {
		return fmt.Errorf("helm: list serviceaccounts in %s: %w", namespace, err)
	}
	names := uniqueNonEmpty(strings.Split(out, "\n"))
	if len(names) == 0 {
		names = []string{"default"}
	}
	patch := fmt.Sprintf(`{"imagePullSecrets":[{"name":%q}]}`, ImagePullSecretName)
	for _, sa := range names {
		if _, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", namespace,
			"patch", "serviceaccount", sa, "--type", "merge", "-p", patch); err != nil {
			return fmt.Errorf("helm: attach image-pull secret to serviceaccount %s/%s: %w", namespace, sa, err)
		}
	}
	return nil
}

func uniqueNonEmpty(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
