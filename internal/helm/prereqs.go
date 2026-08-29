package helm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	cursorHMACFile      = "cursor_hmac.key"
	pepperLength        = 32
)

// requiredKeysSecretFiles is the exact set control-plane LoadOrGenerate expects
// under the mounted keys directory. Installer-managed secrets are read-only in
// the pod, so every name here must be pre-generated; missing files crash the
// process when it tries to generate into a read-only Secret volume.
var requiredKeysSecretFiles = []string{
	sessionPrivateFile,
	registryPrivateFile,
	apiTokenPepperFile,
	refreshPepperFile,
	cursorHMACFile,
}

type chartPrereqs struct {
	KeysSecretName string
}

type secretJSON struct {
	Data map[string]string `json:"data"`
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
	if err := EnsureNamespace(ctx, run, kubeconfig, targetNamespace, nil); err != nil {
		check.Status, check.Message = evidence.StatusFail, err.Error()
		prepared.Checks = append(prepared.Checks, check)
		return prepared, err
	}
	// Read via -o json + map lookup. Secret keys contain dots
	// (registry_ed25519_private.key); kubectl jsonpath treats dots as field
	// separators and bracket forms are version-fragile.
	fileBytes, err := readSecretData(ctx, run, kubeconfig, sourceNamespace, sourceSecret, registryPrivateFile)
	if err != nil {
		check.Status, check.Message = evidence.StatusFail, "control-plane registry signing key is unavailable"
		prepared.Checks = append(prepared.Checks, check)
		return prepared, fmt.Errorf("helm: read registry signing seed from control-plane Secret: %w", err)
	}
	seed, err := decodeEd25519Seed(fileBytes)
	if err != nil {
		return prepared, fmt.Errorf("helm: registry signing key must contain a base64 Ed25519 seed: %w", err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return prepared, fmt.Errorf("helm: marshal registry public key: %w", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	existing, existingErr := readSecretData(ctx, run, kubeconfig, targetNamespace, targetSecret, registryPublicFile)
	if existingErr == nil {
		if !bytes.Equal(existing, publicPEM) {
			check.Status, check.Message = evidence.StatusFail, "registry public verification Secret does not match the control-plane signing key"
			prepared.Checks = append(prepared.Checks, check)
			return prepared, fmt.Errorf("helm: registry public verification Secret is stale or invalid; refusing to start the artifact server")
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

func readSecretData(ctx context.Context, run cli.Runner, kubeconfig, namespace, secretName, key string) ([]byte, error) {
	out, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", namespace,
		"get", "secret", secretName, "-o", "json")
	if err != nil {
		return nil, err
	}
	payload, err := extractJSONObject(out)
	if err != nil {
		return nil, fmt.Errorf("parse Secret %s/%s JSON: %w", namespace, secretName, err)
	}
	var secret secretJSON
	if err := json.Unmarshal(payload, &secret); err != nil {
		return nil, fmt.Errorf("decode Secret %s/%s JSON: %w", namespace, secretName, err)
	}
	encoded, ok := secret.Data[key]
	if !ok || strings.TrimSpace(encoded) == "" {
		return nil, fmt.Errorf("Secret %s/%s missing data key %q", namespace, secretName, key)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("decode Secret %s/%s key %q: %w", namespace, secretName, key, err)
	}
	return raw, nil
}

func extractJSONObject(out string) ([]byte, error) {
	start := strings.Index(out, "{")
	end := strings.LastIndex(out, "}")
	if start < 0 || end < start {
		return nil, fmt.Errorf("no JSON object in command output")
	}
	return []byte(out[start : end+1]), nil
}

// decodeEd25519Seed accepts the installer-managed format (base64 text of a
// 32-byte seed) and also a raw 32-byte seed for resilience.
func decodeEd25519Seed(fileBytes []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(fileBytes)
	if len(trimmed) == ed25519.SeedSize {
		seed := make([]byte, ed25519.SeedSize)
		copy(seed, trimmed)
		return seed, nil
	}
	seed, err := base64.StdEncoding.DecodeString(string(trimmed))
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed length %d, want %d", len(seed), ed25519.SeedSize)
	}
	return seed, nil
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
	if err := EnsureNamespace(ctx, run, kubeconfig, rel.Namespace, rel.NamespaceLabels); err != nil {
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
			if err := ensureKeysSecretComplete(ctx, run, kubeconfig, namespace, secretName); err != nil {
				check.Status = evidence.StatusFail
				check.Message = err.Error()
				return false, check, err
			}
			check.Status = evidence.StatusPass
			check.Message = fmt.Sprintf("installer-managed keys secret %s already present with required key material", secretName)
			return false, check, nil
		} else if !secretNotFound(err) && !namespaceTerminating(err) && !isTransientKubeError(err) {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			return false, check, fmt.Errorf("helm: inspect installer-managed keys secret %s: %w", secretName, err)
		}

		if err := EnsureNamespace(ctx, run, kubeconfig, namespace, nil); err != nil {
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
			}
			for _, name := range requiredKeysSecretFiles {
				args = append(args, "--from-file="+filepath.Join(tempDir, name))
			}
			_, err := run(ctx, "kubectl", args...)
			return err
		}()
		if createErr == nil || secretAlreadyExists(createErr) {
			if secretAlreadyExists(createErr) {
				if err := ensureKeysSecretComplete(ctx, run, kubeconfig, namespace, secretName); err != nil {
					check.Status = evidence.StatusFail
					check.Message = err.Error()
					return false, check, err
				}
				check.Status = evidence.StatusPass
				check.Message = fmt.Sprintf("installer-managed keys secret %s already present with required key material", secretName)
				return false, check, nil
			}
			check.Status = evidence.StatusPass
			check.Message = fmt.Sprintf("created installer-managed keys secret %s", secretName)
			return true, check, nil
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

// ensureKeysSecretComplete loads the existing keys secret and patches in any
// required files that an older installer omitted (for example cursor_hmac.key).
// Existing key material is never rotated; only missing names are generated.
func ensureKeysSecretComplete(ctx context.Context, run cli.Runner, kubeconfig, namespace, secretName string) error {
	out, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", namespace,
		"get", "secret", secretName, "-o", "json")
	if err != nil {
		return fmt.Errorf("helm: read installer-managed keys secret %s: %w", secretName, err)
	}
	payload, err := extractJSONObject(out)
	if err != nil {
		return fmt.Errorf("helm: parse installer-managed keys secret %s: %w", secretName, err)
	}
	var secret secretJSON
	if err := json.Unmarshal(payload, &secret); err != nil {
		return fmt.Errorf("helm: decode installer-managed keys secret %s: %w", secretName, err)
	}
	if secret.Data == nil {
		secret.Data = map[string]string{}
	}

	missing := make([]string, 0, len(requiredKeysSecretFiles))
	for _, name := range requiredKeysSecretFiles {
		if strings.TrimSpace(secret.Data[name]) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}

	patchData := make(map[string]string, len(missing))
	for _, name := range missing {
		raw, err := generateKeysSecretFileContent(name)
		if err != nil {
			return fmt.Errorf("helm: generate missing key material %s: %w", name, err)
		}
		// Secret.data values are base64-encoded file bytes.
		patchData[name] = base64.StdEncoding.EncodeToString(raw)
	}
	body, err := json.Marshal(map[string]any{"data": patchData})
	if err != nil {
		return fmt.Errorf("helm: marshal keys secret patch: %w", err)
	}
	if _, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", namespace,
		"patch", "secret", secretName, "--type", "merge", "-p", string(body)); err != nil {
		return fmt.Errorf("helm: patch installer-managed keys secret %s with missing files %v: %w", secretName, missing, err)
	}
	return nil
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

// EnsureKeysSecretReplica copies the control-plane keys Secret into targetNamespace
// so co-packaged apps that mount keysSecretName (automation-runtime in ace-apps)
// can attach volumes. Material is cloned from source, never regenerated, so
// pods across namespaces see the same signing seeds and peppers.
//
// If the target already exists, any missing required key is filled from the
// source; conflicting values (same name, different content) fail closed.
func EnsureKeysSecretReplica(ctx context.Context, run cli.Runner, kubeconfig, sourceNamespace, targetNamespace, secretName string) (PreparedRelease, error) {
	prepared := PreparedRelease{}
	check := evidence.Check{
		ID:              "chart-prereq-secret-replica-" + evidence.SanitizeIDSegment(secretName),
		Category:        "chart",
		Timestamp:       time.Now().UTC(),
		Idempotent:      true,
		SecretsRedacted: true,
	}
	secretName = strings.TrimSpace(secretName)
	sourceNamespace = strings.TrimSpace(sourceNamespace)
	targetNamespace = strings.TrimSpace(targetNamespace)
	if secretName == "" || sourceNamespace == "" || targetNamespace == "" {
		check.Status = evidence.StatusSkipped
		check.Message = "keys secret replica not requested"
		prepared.Checks = append(prepared.Checks, check)
		return prepared, nil
	}
	if sourceNamespace == targetNamespace {
		check.Status = evidence.StatusSkipped
		check.Message = "keys secret replica not needed; source and target namespaces match"
		prepared.Checks = append(prepared.Checks, check)
		return prepared, nil
	}

	if err := EnsureNamespace(ctx, run, kubeconfig, targetNamespace, nil); err != nil {
		check.Status, check.Message = evidence.StatusFail, err.Error()
		prepared.Checks = append(prepared.Checks, check)
		return prepared, err
	}

	sourceOut, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", sourceNamespace,
		"get", "secret", secretName, "-o", "json")
	if err != nil {
		check.Status, check.Message = evidence.StatusFail, err.Error()
		prepared.Checks = append(prepared.Checks, check)
		return prepared, fmt.Errorf("helm: read source keys secret %s/%s for replica: %w", sourceNamespace, secretName, err)
	}
	sourcePayload, err := extractJSONObject(sourceOut)
	if err != nil {
		return prepared, fmt.Errorf("helm: parse source keys secret %s: %w", secretName, err)
	}
	var sourceSecret secretJSON
	if err := json.Unmarshal(sourcePayload, &sourceSecret); err != nil {
		return prepared, fmt.Errorf("helm: decode source keys secret %s: %w", secretName, err)
	}
	if sourceSecret.Data == nil {
		sourceSecret.Data = map[string]string{}
	}
	for _, name := range requiredKeysSecretFiles {
		if strings.TrimSpace(sourceSecret.Data[name]) == "" {
			check.Status = evidence.StatusFail
			check.Message = fmt.Sprintf("source keys secret %s is missing %s", secretName, name)
			prepared.Checks = append(prepared.Checks, check)
			return prepared, fmt.Errorf("helm: source keys secret %s missing required file %s", secretName, name)
		}
	}

	targetOut, targetErr := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", targetNamespace,
		"get", "secret", secretName, "-o", "json")
	if targetErr == nil {
		targetPayload, parseErr := extractJSONObject(targetOut)
		if parseErr != nil {
			return prepared, fmt.Errorf("helm: parse target keys secret %s: %w", secretName, parseErr)
		}
		var targetSecret secretJSON
		if err := json.Unmarshal(targetPayload, &targetSecret); err != nil {
			return prepared, fmt.Errorf("helm: decode target keys secret %s: %w", secretName, err)
		}
		if targetSecret.Data == nil {
			targetSecret.Data = map[string]string{}
		}
		patchData := map[string]string{}
		for _, name := range requiredKeysSecretFiles {
			want := strings.TrimSpace(sourceSecret.Data[name])
			have := strings.TrimSpace(targetSecret.Data[name])
			if have == "" {
				patchData[name] = want
				continue
			}
			if have != want {
				check.Status = evidence.StatusFail
				check.Message = fmt.Sprintf("keys secret %s in %s conflicts with control-plane copy for %s", secretName, targetNamespace, name)
				prepared.Checks = append(prepared.Checks, check)
				return prepared, fmt.Errorf("helm: keys secret replica conflict for %s in %s", name, targetNamespace)
			}
		}
		if len(patchData) > 0 {
			body, err := json.Marshal(map[string]any{"data": patchData})
			if err != nil {
				return prepared, fmt.Errorf("helm: marshal keys secret replica patch: %w", err)
			}
			if _, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", targetNamespace,
				"patch", "secret", secretName, "--type", "merge", "-p", string(body)); err != nil {
				check.Status, check.Message = evidence.StatusFail, err.Error()
				prepared.Checks = append(prepared.Checks, check)
				return prepared, fmt.Errorf("helm: patch keys secret replica %s: %w", secretName, err)
			}
			check.Status = evidence.StatusPass
			check.Message = fmt.Sprintf("patched keys secret replica %s in %s from control-plane secret", secretName, targetNamespace)
			prepared.Checks = append(prepared.Checks, check)
			return prepared, nil
		}
		check.Status = evidence.StatusPass
		check.Message = fmt.Sprintf("keys secret replica %s already present in %s", secretName, targetNamespace)
		prepared.Checks = append(prepared.Checks, check)
		return prepared, nil
	}
	if !secretNotFound(targetErr) {
		check.Status, check.Message = evidence.StatusFail, targetErr.Error()
		prepared.Checks = append(prepared.Checks, check)
		return prepared, fmt.Errorf("helm: inspect keys secret replica %s: %w", secretName, targetErr)
	}

	tempDir, err := os.MkdirTemp("", "appliance-keys-replica-*")
	if err != nil {
		check.Status, check.Message = evidence.StatusFail, err.Error()
		prepared.Checks = append(prepared.Checks, check)
		return prepared, fmt.Errorf("helm: create temp dir for keys secret replica: %w", err)
	}
	created := false
	createErr := func() error {
		defer os.RemoveAll(tempDir)
		for _, name := range requiredKeysSecretFiles {
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sourceSecret.Data[name]))
			if err != nil {
				return fmt.Errorf("decode source keys secret file %s: %w", name, err)
			}
			if err := os.WriteFile(filepath.Join(tempDir, name), raw, 0o600); err != nil {
				return fmt.Errorf("write replica key file %s: %w", name, err)
			}
		}
		args := []string{
			"--kubeconfig", kubeconfig,
			"--namespace", targetNamespace,
			"create", "secret", "generic", secretName,
		}
		for _, name := range requiredKeysSecretFiles {
			args = append(args, "--from-file="+filepath.Join(tempDir, name))
		}
		_, err := run(ctx, "kubectl", args...)
		return err
	}()
	if createErr != nil && !secretAlreadyExists(createErr) {
		check.Status, check.Message = evidence.StatusFail, createErr.Error()
		prepared.Checks = append(prepared.Checks, check)
		return prepared, fmt.Errorf("helm: create keys secret replica %s in %s: %w", secretName, targetNamespace, createErr)
	}
	if createErr == nil {
		created = true
		prepared.cleanups = append(prepared.cleanups, func() error {
			return deleteSecret(ctx, run, kubeconfig, targetNamespace, secretName)
		})
	}
	check.Status = evidence.StatusPass
	if created {
		check.Message = fmt.Sprintf("created keys secret replica %s in %s from control-plane secret", secretName, targetNamespace)
	} else {
		check.Message = fmt.Sprintf("keys secret replica %s already present in %s", secretName, targetNamespace)
	}
	prepared.Checks = append(prepared.Checks, check)
	return prepared, nil
}

// EnsureBlobStorageCredentialsReplica mirrors the two S3 credentials into the
// control-plane namespace. Kubernetes Secrets are namespace-scoped, while the
// S3 service intentionally lives in ace-infra.
func EnsureBlobStorageCredentialsReplica(ctx context.Context, run cli.Runner, kubeconfig, sourceNamespace, targetNamespace, secretName string) (PreparedRelease, error) {
	prepared := PreparedRelease{}
	if err := EnsureNamespace(ctx, run, kubeconfig, targetNamespace, nil); err != nil {
		return prepared, err
	}
	sourceOut, err := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", sourceNamespace, "get", "secret", secretName, "-o", "json")
	if err != nil {
		return prepared, fmt.Errorf("helm: read blob credentials %s/%s: %w", sourceNamespace, secretName, err)
	}
	sourcePayload, err := extractJSONObject(sourceOut)
	if err != nil {
		return prepared, err
	}
	var source secretJSON
	if err := json.Unmarshal(sourcePayload, &source); err != nil {
		return prepared, err
	}
	for _, key := range []string{"accessKey", "secretKey"} {
		if strings.TrimSpace(source.Data[key]) == "" {
			return prepared, fmt.Errorf("helm: blob credentials %s missing %s", secretName, key)
		}
	}
	targetOut, targetErr := run(ctx, "kubectl", "--kubeconfig", kubeconfig, "--namespace", targetNamespace, "get", "secret", secretName, "-o", "json")
	if targetErr == nil {
		targetPayload, err := extractJSONObject(targetOut)
		if err != nil {
			return prepared, err
		}
		var target secretJSON
		if err := json.Unmarshal(targetPayload, &target); err != nil {
			return prepared, err
		}
		for _, key := range []string{"accessKey", "secretKey"} {
			if strings.TrimSpace(target.Data[key]) != source.Data[key] {
				return prepared, fmt.Errorf("helm: blob credentials conflict for %s in %s", key, targetNamespace)
			}
		}
		return prepared, nil
	}
	if !secretNotFound(targetErr) {
		return prepared, targetErr
	}
	tempDir, err := os.MkdirTemp("", "appliance-blob-credentials-*")
	if err != nil {
		return prepared, err
	}
	defer os.RemoveAll(tempDir)
	args := []string{"--kubeconfig", kubeconfig, "--namespace", targetNamespace, "create", "secret", "generic", secretName}
	for _, key := range []string{"accessKey", "secretKey"} {
		raw, err := base64.StdEncoding.DecodeString(source.Data[key])
		if err != nil {
			return prepared, err
		}
		path := filepath.Join(tempDir, key)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			return prepared, err
		}
		args = append(args, "--from-file="+path)
	}
	if _, err := run(ctx, "kubectl", args...); err != nil && !secretAlreadyExists(err) {
		return prepared, fmt.Errorf("helm: create blob credential replica: %w", err)
	}
	prepared.Checks = append(prepared.Checks, evidence.Check{ID: "chart-prereq-blob-credentials-replica", Category: "chart", Status: evidence.StatusPass, Message: fmt.Sprintf("replicated blob credentials into %s", targetNamespace), Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true})
	return prepared, nil
}

func writeKeysSecretFiles(dir string) error {
	for _, name := range requiredKeysSecretFiles {
		content, err := generateKeysSecretFileContent(name)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			return fmt.Errorf("write keys secret file %s: %w", name, err)
		}
	}
	return nil
}

func generateKeysSecretFileContent(name string) ([]byte, error) {
	switch name {
	case sessionPrivateFile, registryPrivateFile:
		seed, err := generateEd25519Seed()
		if err != nil {
			return nil, err
		}
		return []byte(base64.StdEncoding.EncodeToString(seed)), nil
	case apiTokenPepperFile, refreshPepperFile, cursorHMACFile:
		raw, err := generateRandomBytes(pepperLength)
		if err != nil {
			return nil, err
		}
		return []byte(base64.StdEncoding.EncodeToString(raw)), nil
	default:
		return nil, fmt.Errorf("unsupported keys secret file %q", name)
	}
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
