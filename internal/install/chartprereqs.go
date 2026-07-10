package install

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"gopkg.in/yaml.v3"
)

const (
	sessionPrivateFile  = "session_ed25519_private.key"
	registryPrivateFile = "registry_ed25519_private.key"
	apiTokenPepperFile  = "api_token_pepper.key"
	refreshPepperFile   = "refresh_pepper.key"
	pepperLength        = 32
)

type chartValues struct {
	Secrets struct {
		KeysSecretName string `yaml:"keysSecretName"`
	} `yaml:"secrets"`
}

type chartPrereqs struct {
	KeysSecretName string
}

func loadChartPrereqs(valuesPath string) (chartPrereqs, error) {
	data, err := os.ReadFile(valuesPath)
	if err != nil {
		return chartPrereqs{}, fmt.Errorf("install: read chart values %s: %w", valuesPath, err)
	}

	var values chartValues
	if err := yaml.Unmarshal(data, &values); err != nil {
		return chartPrereqs{}, fmt.Errorf("install: parse chart values %s: %w", valuesPath, err)
	}

	return chartPrereqs{
		KeysSecretName: strings.TrimSpace(values.Secrets.KeysSecretName),
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

	if _, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", namespace, "get", "secret", secretName); err == nil {
		check.Status = evidence.StatusPass
		check.Message = fmt.Sprintf("installer-managed keys secret %s already present", secretName)
		return false, check, nil
	}

	tempDir, err := os.MkdirTemp("", "appliance-keys-*")
	if err != nil {
		check.Status = evidence.StatusFail
		check.Message = err.Error()
		return false, check, fmt.Errorf("install: create temp dir for keys secret: %w", err)
	}
	defer os.RemoveAll(tempDir)

	if err := writeKeysSecretFiles(tempDir); err != nil {
		check.Status = evidence.StatusFail
		check.Message = err.Error()
		return false, check, fmt.Errorf("install: prepare keys secret files: %w", err)
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
	if _, err := run(ctx, "kubectl", args...); err != nil {
		check.Status = evidence.StatusFail
		check.Message = err.Error()
		return false, check, fmt.Errorf("install: create installer-managed keys secret %s: %w", secretName, err)
	}

	check.Status = evidence.StatusPass
	check.Message = fmt.Sprintf("created installer-managed keys secret %s", secretName)
	return true, check, nil
}

func deleteSecret(ctx context.Context, run cli.Runner, kubeconfig, namespace, secretName string) error {
	if secretName == "" {
		return nil
	}
	_, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", namespace, "delete", "secret", secretName, "--ignore-not-found")
	if err != nil {
		return fmt.Errorf("install: delete installer-managed keys secret %s: %w", secretName, err)
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
