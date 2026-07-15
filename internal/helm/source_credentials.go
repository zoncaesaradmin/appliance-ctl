package helm

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
)

type SourceCredentialSecret struct {
	Namespace            string
	SecretName           string
	PrivateKeyPath       string
	KnownHostsSecretName string
	KnownHostsPath       string
}

func EnsureSourceCredentialSecrets(ctx context.Context, run cli.Runner, kubeconfig string, creds []SourceCredentialSecret) (PreparedRelease, error) {
	prepared := PreparedRelease{}
	for _, cred := range creds {
		created, check, err := ensureFileSecret(ctx, run, kubeconfig, cred.Namespace, cred.SecretName, "ssh-privatekey", cred.PrivateKeyPath, "source credential")
		prepared.Checks = append(prepared.Checks, check)
		if err != nil {
			return prepared, err
		}
		if created {
			namespace, secretName := cred.Namespace, cred.SecretName
			prepared.cleanups = append(prepared.cleanups, func() error { return deleteSecret(ctx, run, kubeconfig, namespace, secretName) })
		}
		if cred.KnownHostsSecretName != "" {
			created, check, err = ensureFileSecret(ctx, run, kubeconfig, cred.Namespace, cred.KnownHostsSecretName, "known_hosts", cred.KnownHostsPath, "source known_hosts")
			prepared.Checks = append(prepared.Checks, check)
			if err != nil {
				return prepared, err
			}
			if created {
				namespace, secretName := cred.Namespace, cred.KnownHostsSecretName
				prepared.cleanups = append(prepared.cleanups, func() error { return deleteSecret(ctx, run, kubeconfig, namespace, secretName) })
			}
		}
	}
	return prepared, nil
}

func ensureFileSecret(ctx context.Context, run cli.Runner, kubeconfig, namespace, secretName, key, path, label string) (bool, evidence.Check, error) {
	check := evidence.Check{ID: "chart-prereq-secret-" + evidence.SanitizeIDSegment(secretName), Category: "chart", Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true}
	if _, err := os.Stat(path); err != nil {
		check.Status = evidence.StatusFail
		check.Message = fmt.Sprintf("%s file is not readable: %v", label, err)
		return false, check, fmt.Errorf("helm: inspect %s file for secret %s: %w", label, secretName, err)
	}
	if err := EnsureNamespace(ctx, run, kubeconfig, namespace); err != nil {
		check.Status = evidence.StatusFail
		check.Message = err.Error()
		return false, check, err
	}
	if _, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", namespace, "get", "secret", secretName); err == nil {
		check.Status = evidence.StatusPass
		check.Message = fmt.Sprintf("%s secret %s already present", label, secretName)
		return false, check, nil
	} else if !secretNotFound(err) && !isTransientKubeError(err) {
		check.Status = evidence.StatusFail
		check.Message = err.Error()
		return false, check, fmt.Errorf("helm: inspect %s secret %s: %w", label, secretName, err)
	}
	_, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", namespace, "create", "secret", "generic", secretName, "--from-file="+key+"="+path)
	if err != nil && !secretAlreadyExists(err) {
		check.Status = evidence.StatusFail
		check.Message = err.Error()
		return false, check, fmt.Errorf("helm: create %s secret %s: %w", label, secretName, err)
	}
	check.Status = evidence.StatusPass
	if err == nil {
		check.Message = fmt.Sprintf("created %s secret %s", label, secretName)
		return true, check, nil
	}
	check.Message = fmt.Sprintf("%s secret %s already present", label, secretName)
	return false, check, nil
}
