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
		Namespace:  "ace-apps",
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
		Namespace:  "ace-apps",
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
