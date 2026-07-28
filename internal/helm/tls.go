package helm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/appliancetls"
	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
)

const (
	// DefaultApplianceTLSSecret is the kubernetes.io/tls Secret name referenced by
	// control-plane and registry IngressRoutes (charts' ingress.tlsSecretName).
	DefaultApplianceTLSSecret = "appliance-tls"
	// DefaultApplianceCASecret stores the installer-generated CA used to
	// reissue leaf certificates. Public CA export for clients is separate.
	DefaultApplianceCASecret = "appliance-ca"

	caCertFileName  = "ca.crt"
	caKeyFileName   = "ca.key"
	tlsCertFileName = "tls.crt"
	tlsKeyFileName  = "tls.key"
)

// ApplianceTLSOptions configures installer-managed Traefik HTTPS material.
type ApplianceTLSOptions struct {
	ControlNamespace  string
	ArtifactNamespace string
	IncludeArtifacts  bool
	FQDN              string
	NodeIPv4          string
	ExtraSANs         []string
	TLSSecretName     string
	CASecretName      string
}

// EnsureApplianceTLSSecrets ensures an appliance CA exists in the control
// namespace and that kubernetes.io/tls Secrets covering the appliance FQDN and
// preferred node IP (plus extras) exist in every namespace that serves
// IngressRoutes with tls.secretName appliance-tls.
func EnsureApplianceTLSSecrets(ctx context.Context, run cli.Runner, kubeconfig string, opts ApplianceTLSOptions) (PreparedRelease, error) {
	prepared := PreparedRelease{}
	check := evidence.Check{
		ID: "chart-prereq-secret-appliance-tls", Category: "chart",
		Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	}

	controlNS := strings.TrimSpace(opts.ControlNamespace)
	if controlNS == "" {
		check.Status, check.Message = evidence.StatusFail, "control namespace is required for appliance TLS"
		prepared.Checks = append(prepared.Checks, check)
		return prepared, fmt.Errorf("helm: appliance TLS control namespace is empty")
	}
	tlsSecret := strings.TrimSpace(opts.TLSSecretName)
	if tlsSecret == "" {
		tlsSecret = DefaultApplianceTLSSecret
	}
	caSecret := strings.TrimSpace(opts.CASecretName)
	if caSecret == "" {
		caSecret = DefaultApplianceCASecret
	}

	sans := appliancetls.BuildSANs(opts.FQDN, opts.NodeIPv4, opts.ExtraSANs)
	if len(sans.DNSNames) == 0 && len(sans.IPAddresses) == 0 {
		check.Status, check.Message = evidence.StatusFail, "appliance TLS requires FQDN or IP SANs"
		prepared.Checks = append(prepared.Checks, check)
		return prepared, fmt.Errorf("helm: appliance TLS SAN list is empty")
	}

	if err := EnsureNamespace(ctx, run, kubeconfig, controlNS, nil); err != nil {
		check.Status, check.Message = evidence.StatusFail, err.Error()
		prepared.Checks = append(prepared.Checks, check)
		return prepared, err
	}

	namespaces := []string{controlNS}
	if opts.IncludeArtifacts {
		artifactNS := strings.TrimSpace(opts.ArtifactNamespace)
		if artifactNS == "" {
			check.Status, check.Message = evidence.StatusFail, "artifact namespace is required when IncludeArtifacts is set"
			prepared.Checks = append(prepared.Checks, check)
			return prepared, fmt.Errorf("helm: appliance TLS artifact namespace is empty")
		}
		if err := EnsureNamespace(ctx, run, kubeconfig, artifactNS, nil); err != nil {
			check.Status, check.Message = evidence.StatusFail, err.Error()
			prepared.Checks = append(prepared.Checks, check)
			return prepared, err
		}
		if artifactNS != controlNS {
			namespaces = append(namespaces, artifactNS)
		}
	}

	caCertPEM, caKeyPEM, caCreated, err := ensureApplianceCA(ctx, run, kubeconfig, controlNS, caSecret)
	if err != nil {
		check.Status, check.Message = evidence.StatusFail, err.Error()
		prepared.Checks = append(prepared.Checks, check)
		return prepared, err
	}
	if caCreated {
		prepared.cleanups = append(prepared.cleanups, func() error {
			return deleteSecret(ctx, run, kubeconfig, controlNS, caSecret)
		})
	}

	leafCertPEM, leafKeyPEM, err := appliancetls.IssueLeaf(caCertPEM, caKeyPEM, sans)
	if err != nil {
		check.Status, check.Message = evidence.StatusFail, err.Error()
		prepared.Checks = append(prepared.Checks, check)
		return prepared, err
	}

	updated := 0
	for _, ns := range namespaces {
		changed, err := ensureTLSSecret(ctx, run, kubeconfig, ns, tlsSecret, leafCertPEM, leafKeyPEM, sans)
		if err != nil {
			check.Status, check.Message = evidence.StatusFail, err.Error()
			prepared.Checks = append(prepared.Checks, check)
			return prepared, err
		}
		if changed {
			updated++
			ns := ns
			prepared.cleanups = append(prepared.cleanups, func() error {
				return deleteSecret(ctx, run, kubeconfig, ns, tlsSecret)
			})
		}
	}

	check.Status = evidence.StatusPass
	if updated == 0 {
		check.Message = fmt.Sprintf("%s already covers required SANs in %s", tlsSecret, strings.Join(namespaces, ","))
	} else {
		check.Message = fmt.Sprintf("ensured %s with appliance FQDN/IP SANs in %s", tlsSecret, strings.Join(namespaces, ","))
	}
	prepared.Checks = append(prepared.Checks, check)
	return prepared, nil
}

func ensureApplianceCA(ctx context.Context, run cli.Runner, kubeconfig, namespace, secretName string) (certPEM, keyPEM []byte, created bool, err error) {
	existingCert, certErr := readSecretData(ctx, run, kubeconfig, namespace, secretName, caCertFileName)
	existingKey, keyErr := readSecretData(ctx, run, kubeconfig, namespace, secretName, caKeyFileName)
	if certErr == nil && keyErr == nil {
		if _, parseErr := appliancetls.ParseCertificatePEM(existingCert); parseErr == nil {
			return existingCert, existingKey, false, nil
		}
	}
	if certErr != nil && !secretNotFound(certErr) {
		return nil, nil, false, fmt.Errorf("helm: read appliance CA certificate: %w", certErr)
	}
	if keyErr != nil && !secretNotFound(keyErr) {
		return nil, nil, false, fmt.Errorf("helm: read appliance CA key: %w", keyErr)
	}

	certPEM, keyPEM, err = appliancetls.GenerateCA()
	if err != nil {
		return nil, nil, false, err
	}
	tempDir, err := os.MkdirTemp("", "appliance-ca-*")
	if err != nil {
		return nil, nil, false, fmt.Errorf("helm: create CA temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)
	certPath := filepath.Join(tempDir, caCertFileName)
	keyPath := filepath.Join(tempDir, caKeyFileName)
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, nil, false, fmt.Errorf("helm: write CA certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, nil, false, fmt.Errorf("helm: write CA key: %w", err)
	}
	// Replace any incomplete/stale CA secret before create.
	_ = deleteSecret(ctx, run, kubeconfig, namespace, secretName)
	if _, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", namespace,
		"create", "secret", "generic", secretName,
		"--from-file="+certPath,
		"--from-file="+keyPath); err != nil && !secretAlreadyExists(err) {
		return nil, nil, false, fmt.Errorf("helm: create appliance CA Secret: %w", err)
	}
	return certPEM, keyPEM, true, nil
}

func ensureTLSSecret(ctx context.Context, run cli.Runner, kubeconfig, namespace, secretName string, leafCertPEM, leafKeyPEM []byte, want appliancetls.SANs) (changed bool, err error) {
	existing, readErr := readSecretData(ctx, run, kubeconfig, namespace, secretName, tlsCertFileName)
	if readErr == nil {
		if cert, parseErr := appliancetls.ParseCertificatePEM(existing); parseErr == nil && want.Equal(cert) {
			return false, nil
		}
	} else if !secretNotFound(readErr) {
		return false, fmt.Errorf("helm: inspect %s/%s: %w", namespace, secretName, readErr)
	}

	tempDir, err := os.MkdirTemp("", "appliance-tls-*")
	if err != nil {
		return false, fmt.Errorf("helm: create TLS temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)
	certPath := filepath.Join(tempDir, tlsCertFileName)
	keyPath := filepath.Join(tempDir, tlsKeyFileName)
	if err := os.WriteFile(certPath, leafCertPEM, 0o600); err != nil {
		return false, fmt.Errorf("helm: write leaf certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, leafKeyPEM, 0o600); err != nil {
		return false, fmt.Errorf("helm: write leaf key: %w", err)
	}
	_ = deleteSecret(ctx, run, kubeconfig, namespace, secretName)
	if _, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", namespace,
		"create", "secret", "tls", secretName,
		"--cert="+certPath,
		"--key="+keyPath); err != nil && !secretAlreadyExists(err) {
		return false, fmt.Errorf("helm: create %s/%s: %w", namespace, secretName, err)
	}
	return true, nil
}
