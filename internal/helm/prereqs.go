package helm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
)

const (
	sessionPrivateFile  = "session_ed25519_private.key"
	registryPrivateFile = "registry_ed25519_private.key"
	registryPublicFile  = "registry_ed25519_public.pem"
	apiTokenPepperFile  = "api_token_pepper.key"
	refreshPepperFile   = "refresh_pepper.key"
	pepperLength        = 32
)

type chartPrereqs struct {
	KeysSecretName string
}

// EnsureRegistryPublicKeySecret derives the registry verification key from
// the control-plane signing seed and creates a target Secret containing only
// public material. The private seed never leaves its original Secret.
func EnsureRegistryPublicKeySecret(ctx context.Context, run cli.Runner, kubeconfig, sourceNamespace, sourceSecret, targetNamespace, targetSecret string) (PreparedRelease, error) {
	prepared := PreparedRelease{}
	check := evidence.Check{
		ID:       "chart-prereq-secret-" + evidence.SanitizeIDSegment(targetSecret),
		Category: "chart", Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
	}
	if err := EnsureNamespace(ctx, run, kubeconfig, targetNamespace); err != nil {
		check.Status, check.Message = evidence.StatusFail, err.Error()
		prepared.Checks = append(prepared.Checks, check)
		return prepared, err
	}
	// Secret keys contain dots (e.g. registry_ed25519_private.key). Plain
	// jsonpath={.data.foo.bar} walks nested fields; bracket form is required.
	encodedFile, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", sourceNamespace,
		"get", "secret", sourceSecret, "-o", secretDataJSONPath(registryPrivateFile))
	if err != nil {
		check.Status, check.Message = evidence.StatusFail, "control-plane registry signing key is unavailable"
		prepared.Checks = append(prepared.Checks, check)
		return prepared, fmt.Errorf("helm: read registry signing seed from control-plane Secret: %w", err)
	}
	fileBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedFile))
	if err != nil {
		return prepared, fmt.Errorf("helm: decode registry signing key Secret data: %w", err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(fileBytes)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return prepared, fmt.Errorf("helm: registry signing key must contain a base64 Ed25519 seed")
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return prepared, fmt.Errorf("helm: marshal registry public key: %w", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	existingEncoded, existingErr := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", targetNamespace,
		"get", "secret", targetSecret, "-o", secretDataJSONPath(registryPublicFile))
	if existingErr == nil {
		existing, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(existingEncoded))
		if decodeErr != nil || !bytes.Equal(existing, publicPEM) {
			check.Status, check.Message = evidence.StatusFail, "registry public verification Secret does not match the control-plane signing key"
			prepared.Checks = append(prepared.Checks, check)
			return prepared, fmt.Errorf("helm: registry public verification Secret is stale or invalid; refusing to start zot")
		}
		check.Status, check.Message = evidence.StatusPass, fmt.Sprintf("registry public verification Secret %s matches the control-plane signing key", targetSecret)
		prepared.Checks = append(prepared.Checks, check)
		return prepared, nil
	}
	if !secretNotFound(existingErr) {
		check.Status, check.Message = evidence.StatusFail, existingErr.Error()
		prepared.Checks = append(prepared.Checks, check)
		return prepared, fmt.Errorf("helm: inspect registry public verification Secret: %w", existingErr)
	}
	tempDir, err := os.MkdirTemp("", "appliance-registry-public-*")
	if err != nil {
		return prepared, fmt.Errorf("helm: create registry public-key temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)
	publicPath := filepath.Join(tempDir, registryPublicFile)
	if err := os.WriteFile(publicPath, publicPEM, 0o600); err != nil {
		return prepared, fmt.Errorf("helm: write registry public key: %w", err)
	}
	if _, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", targetNamespace,
		"create", "secret", "generic", targetSecret, "--from-file="+publicPath); err != nil && !secretAlreadyExists(err) {
		check.Status, check.Message = evidence.StatusFail, err.Error()
		prepared.Checks = append(prepared.Checks, check)
		return prepared, fmt.Errorf("helm: create registry public verification Secret: %w", err)
	}
	check.Status, check.Message = evidence.StatusPass, fmt.Sprintf("created registry public verification Secret %s without private material", targetSecret)
	prepared.Checks = append(prepared.Checks, check)
	prepared.cleanups = append(prepared.cleanups, func() error {
		return deleteSecret(ctx, run, kubeconfig, targetNamespace, targetSecret)
	})
	return prepared, nil
}

// PreparedRelease captures prerequisite evidence plus any cleanup the
// installer/upgrader should run if a later step fails. The cleanup is
// intentionally idempotent so reruns can reuse the same code path.
type PreparedRelease struct {
	Checks   []evidence.Check
	cleanups []func() error
}

// Cleanup runs release-prerequisite rollback in reverse order and returns
// every encountered cleanup error, if any.
func (p PreparedRelease) Cleanup() error {
	var errs []error
	for i := len(p.cleanups) - 1; i >= 0; i-- {
		if err := p.cleanups[i](); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// EnsureReleasePrereqs makes a release namespace usable and provisions any
// installer-managed Kubernetes objects the chart values declare. This is
// shared by both install and upgrade so reruns behave consistently.
func EnsureReleasePrereqs(ctx context.Context, run cli.Runner, kubeconfig string, rel ChartRelease) (PreparedRelease, error) {
	if err := EnsureNamespace(ctx, run, kubeconfig, rel.Namespace); err != nil {
		return PreparedRelease{}, err
	}
	if strings.TrimSpace(rel.ValuesPath) == "" {
		return PreparedRelease{}, nil
	}

	prereqs, err := loadChartPrereqs(rel.ValuesPath)
	if err != nil {
		return PreparedRelease{}, err
	}

	prepared := PreparedRelease{}
	keysSecretCreated, secretCheck, err := ensureKeysSecret(ctx, run, kubeconfig, rel.Namespace, prereqs.KeysSecretName)
	prepared.Checks = append(prepared.Checks, secretCheck)
	if err != nil {
		return prepared, err
	}
	if keysSecretCreated {
		prepared.cleanups = append(prepared.cleanups, func() error {
			return deleteSecret(ctx, run, kubeconfig, rel.Namespace, prereqs.KeysSecretName)
		})
	}

	return prepared, nil
}

func loadChartPrereqs(valuesPath string) (chartPrereqs, error) {
	values, err := loadChartValues(valuesPath)
	if err != nil {
		return chartPrereqs{}, err
	}

	return chartPrereqs{
		KeysSecretName: values.Secrets.KeysSecretName,
	}, nil
}

func ensureKeysSecret(ctx context.Context, run cli.Runner, kubeconfig, namespace, secretName string) (bool, evidence.Check, error) {
	check := evidence.Check{
		ID:              "chart-prereq-secret-" + evidence.SanitizeIDSegment(secretName),
		Category:        "chart",
		Timestamp:       time.Now().UTC(),
		Idempotent:      true,
		SecretsRedacted: true,
	}

	if secretName == "" {
		check.Status = evidence.StatusSkipped
		check.Message = "chart values do not request an installer-managed keys secret"
		return false, check, nil
	}

	deadline := time.Now().Add(namespaceReadyTimeout)
	for {
		if _, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", namespace, "get", "secret", secretName); err == nil {
			check.Status = evidence.StatusPass
			check.Message = fmt.Sprintf("installer-managed keys secret %s already present", secretName)
			return false, check, nil
		} else if !secretNotFound(err) && !namespaceTerminating(err) && !isTransientKubeError(err) {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			return false, check, fmt.Errorf("helm: inspect installer-managed keys secret %s: %w", secretName, err)
		}

		if err := EnsureNamespace(ctx, run, kubeconfig, namespace); err != nil {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			return false, check, err
		}

		tempDir, err := os.MkdirTemp("", "appliance-keys-*")
		if err != nil {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			return false, check, fmt.Errorf("helm: create temp dir for keys secret: %w", err)
		}

		createErr := func() error {
			defer os.RemoveAll(tempDir)

			if err := writeKeysSecretFiles(tempDir); err != nil {
				return fmt.Errorf("helm: prepare keys secret files: %w", err)
			}

			args := []string{
				"--kubeconfig", kubeconfig,
				"--namespace", namespace,
				"create", "secret", "generic", secretName,
				"--from-file=" + filepath.Join(tempDir, sessionPrivateFile),
				"--from-file=" + filepath.Join(tempDir, registryPrivateFile),
				"--from-file=" + filepath.Join(tempDir, apiTokenPepperFile),
				"--from-file=" + filepath.Join(tempDir, refreshPepperFile),
			}
			_, err := run(ctx, "kubectl", args...)
			return err
		}()
		if createErr == nil || secretAlreadyExists(createErr) {
			check.Status = evidence.StatusPass
			if createErr == nil {
				check.Message = fmt.Sprintf("created installer-managed keys secret %s", secretName)
				return true, check, nil
			}
			check.Message = fmt.Sprintf("installer-managed keys secret %s already present", secretName)
			return false, check, nil
		}
		if !namespaceTerminating(createErr) && !isTransientKubeError(createErr) {
			check.Status = evidence.StatusFail
			check.Message = createErr.Error()
			return false, check, fmt.Errorf("helm: create installer-managed keys secret %s: %w", secretName, createErr)
		}
		if time.Now().After(deadline) {
			check.Status = evidence.StatusFail
			check.Message = createErr.Error()
			return false, check, fmt.Errorf("helm: create installer-managed keys secret %s: %w", secretName, createErr)
		}
		if err := waitNamespaceRetry(ctx); err != nil {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			return false, check, err
		}
	}
}

func deleteSecret(ctx context.Context, run cli.Runner, kubeconfig, namespace, secretName string) error {
	if secretName == "" {
		return nil
	}
	_, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", namespace, "delete", "secret", secretName, "--ignore-not-found")
	if err != nil {
		return fmt.Errorf("helm: delete installer-managed keys secret %s: %w", secretName, err)
	}
	return nil
}

func writeKeysSecretFiles(dir string) error {
	sessionKey, err := generateEd25519Seed()
	if err != nil {
		return err
	}
	registryKey, err := generateEd25519Seed()
	if err != nil {
		return err
	}
	apiPepper, err := generateRandomBytes(pepperLength)
	if err != nil {
		return err
	}
	refreshPepper, err := generateRandomBytes(pepperLength)
	if err != nil {
		return err
	}

	files := map[string][]byte{
		sessionPrivateFile:  []byte(base64.StdEncoding.EncodeToString(sessionKey)),
		registryPrivateFile: []byte(base64.StdEncoding.EncodeToString(registryKey)),
		apiTokenPepperFile:  []byte(base64.StdEncoding.EncodeToString(apiPepper)),
		refreshPepperFile:   []byte(base64.StdEncoding.EncodeToString(refreshPepper)),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			return fmt.Errorf("write keys secret file %s: %w", name, err)
		}
	}
	return nil
}

func generateEd25519Seed() ([]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 seed: %w", err)
	}
	return priv.Seed(), nil
}

func generateRandomBytes(length int) ([]byte, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate random bytes: %w", err)
	}
	return buf, nil
}

func secretNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "notfound") || strings.Contains(msg, "not found") || strings.Contains(msg, "missing secret")
}

func secretAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "alreadyexists") || strings.Contains(msg, "already exists")
}

// secretDataJSONPath selects one Secret data key. Keys with dots must use the
// bracket form; otherwise kubectl treats each segment as a nested field.
func secretDataJSONPath(key string) string {
	return "jsonpath={.data['" + key + "']}"
}
