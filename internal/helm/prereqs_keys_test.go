package helm_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/helm"
)

func TestEnsureReleasePrereqsCreatesKeysSecretWithCursorHMAC(t *testing.T) {
	valuesDir := t.TempDir()
	valuesPath := filepath.Join(valuesDir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("secrets:\n  keysSecretName: appliance-keys\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var createArgs []string
	run := func(_ context.Context, name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(call, "get namespace"):
			return "Active", nil
		case strings.Contains(call, "create namespace"):
			return "", nil
		case strings.Contains(call, "label namespace"):
			return "", nil
		case strings.Contains(call, "get secret appliance-keys") && !contains(args, "json"):
			return "", fmt.Errorf(`Error from server (NotFound): secrets "appliance-keys" not found`)
		case strings.Contains(call, "create secret generic appliance-keys"):
			createArgs = append([]string{}, args...)
			return "secret/appliance-keys created", nil
		default:
			return "", fmt.Errorf("unexpected call: %s", call)
		}
	}

	prepared, err := helm.EnsureReleasePrereqs(context.Background(), run, "/kubeconfig", helm.ChartRelease{
		Namespace:  "ace-system",
		ValuesPath: valuesPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.Cleanup(); err != nil {
		// Cleanup may try to delete the secret; runner does not need to handle it.
		_ = err
	}

	fromFiles := map[string]struct{}{}
	for _, arg := range createArgs {
		if !strings.HasPrefix(arg, "--from-file=") {
			continue
		}
		fromFiles[filepath.Base(strings.TrimPrefix(arg, "--from-file="))] = struct{}{}
	}
	for _, name := range []string{
		"session_ed25519_private.key",
		"registry_ed25519_private.key",
		"api_token_pepper.key",
		"refresh_pepper.key",
		"cursor_hmac.key",
	} {
		if _, ok := fromFiles[name]; !ok {
			t.Fatalf("create secret args missing --from-file for %s; got %v", name, createArgs)
		}
	}
}

func TestEnsureReleasePrereqsPatchesMissingCursorHMAC(t *testing.T) {
	valuesDir := t.TempDir()
	valuesPath := filepath.Join(valuesDir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("secrets:\n  keysSecretName: appliance-keys\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	existing := map[string]string{
		"session_ed25519_private.key":  base64.StdEncoding.EncodeToString([]byte("session")),
		"registry_ed25519_private.key": base64.StdEncoding.EncodeToString([]byte("registry")),
		"api_token_pepper.key":         base64.StdEncoding.EncodeToString([]byte("api")),
		"refresh_pepper.key":           base64.StdEncoding.EncodeToString([]byte("refresh")),
	}
	var patchBody string
	run := func(_ context.Context, name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(call, "get namespace"):
			return "Active", nil
		case strings.Contains(call, "label namespace"):
			return "", nil
		case strings.Contains(call, "get secret appliance-keys") && contains(args, "json"):
			payload, _ := json.Marshal(map[string]any{"data": existing})
			return string(payload), nil
		case strings.Contains(call, "get secret appliance-keys"):
			return "appliance-keys", nil
		case strings.Contains(call, "patch secret appliance-keys"):
			for i, arg := range args {
				if arg == "-p" && i+1 < len(args) {
					patchBody = args[i+1]
				}
			}
			return "secret/appliance-keys patched", nil
		default:
			return "", fmt.Errorf("unexpected call: %s", call)
		}
	}

	if _, err := helm.EnsureReleasePrereqs(context.Background(), run, "/kubeconfig", helm.ChartRelease{
		Namespace:  "ace-system",
		ValuesPath: valuesPath,
	}); err != nil {
		t.Fatal(err)
	}
	if patchBody == "" {
		t.Fatal("expected keys secret to be patched with missing cursor_hmac.key")
	}
	var patch map[string]map[string]string
	if err := json.Unmarshal([]byte(patchBody), &patch); err != nil {
		t.Fatalf("patch body is not JSON: %v (%s)", err, patchBody)
	}
	if _, ok := patch["data"]["cursor_hmac.key"]; !ok {
		t.Fatalf("expected cursor_hmac.key in patch data, got %v", patch)
	}
	if _, ok := patch["data"]["session_ed25519_private.key"]; ok {
		t.Fatal("must not rotate existing session key when only cursor_hmac is missing")
	}
}

func TestEnsureKeysSecretReplicaCopiesMaterialToAppsNamespace(t *testing.T) {
	sourceData := map[string]string{
		"session_ed25519_private.key":  base64.StdEncoding.EncodeToString([]byte("session-seed")),
		"registry_ed25519_private.key": base64.StdEncoding.EncodeToString([]byte("registry-seed")),
		"api_token_pepper.key":         base64.StdEncoding.EncodeToString([]byte("api-pepper")),
		"refresh_pepper.key":           base64.StdEncoding.EncodeToString([]byte("refresh-pepper")),
		"cursor_hmac.key":              base64.StdEncoding.EncodeToString([]byte("cursor-secret")),
	}
	var createArgs []string
	run := func(_ context.Context, name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(call, "get namespace"):
			return "Active", nil
		case strings.Contains(call, "create namespace"):
			return "", nil
		case strings.Contains(call, "label namespace"):
			return "", nil
		case strings.Contains(call, "get secret appliance-keys") && strings.Contains(call, "ace-system") && contains(args, "json"):
			payload, _ := json.Marshal(map[string]any{"data": sourceData})
			return string(payload), nil
		case strings.Contains(call, "get secret appliance-keys") && strings.Contains(call, "ace-apps"):
			return "", fmt.Errorf(`Error from server (NotFound): secrets "appliance-keys" not found`)
		case strings.Contains(call, "create secret generic appliance-keys") && strings.Contains(call, "ace-apps"):
			createArgs = append([]string{}, args...)
			return "secret/appliance-keys created", nil
		default:
			return "", fmt.Errorf("unexpected call: %s", call)
		}
	}

	prepared, err := helm.EnsureKeysSecretReplica(context.Background(), run, "/kubeconfig", "ace-system", "ace-apps", "appliance-keys")
	if err != nil {
		t.Fatal(err)
	}
	if len(createArgs) == 0 {
		t.Fatal("expected create secret in ace-apps")
	}
	if !strings.Contains(strings.Join(createArgs, " "), "--namespace") {
		// namespace is in args before create
	}
	foundNS := false
	for i, a := range createArgs {
		if a == "--namespace" && i+1 < len(createArgs) && createArgs[i+1] == "ace-apps" {
			foundNS = true
		}
	}
	if !foundNS {
		t.Fatalf("expected --namespace ace-apps, got %v", createArgs)
	}
	if err := prepared.Cleanup(); err != nil {
		_ = err
	}
}
