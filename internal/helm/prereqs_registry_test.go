package helm_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/helm"
)

func TestEnsureRegistryPublicKeySecretPublishesOnlyDerivedPublicMaterial(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	encodedFile := base64.StdEncoding.EncodeToString(seed)
	kubernetesData := base64.StdEncoding.EncodeToString([]byte(encodedFile))
	var published []byte
	var readPrivateUsedJSON bool

	run := func(_ context.Context, name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(call, "get namespace"):
			return "Active", nil
		case strings.Contains(call, "get secret appliance-keys") && contains(args, "json"):
			readPrivateUsedJSON = true
			payload, _ := json.Marshal(map[string]any{
				"data": map[string]string{
					"registry_ed25519_private.key": kubernetesData,
				},
			})
			return string(payload), nil
		case strings.Contains(call, "get secret appliance-registry-verification-key"):
			return "", fmt.Errorf("secret not found")
		case strings.Contains(call, "create secret generic appliance-registry-verification-key"):
			for _, arg := range args {
				if strings.HasPrefix(arg, "--from-file=") {
					var err error
					published, err = os.ReadFile(strings.TrimPrefix(arg, "--from-file="))
					return "", err
				}
			}
			return "", fmt.Errorf("public key file missing")
		case strings.Contains(call, "delete secret"):
			return "", nil
		default:
			return "", fmt.Errorf("unexpected call: %s", call)
		}
	}

	prepared, err := helm.EnsureRegistryPublicKeySecret(context.Background(), run, "/kubeconfig",
		"appliance-system", "appliance-keys", "registry", "appliance-registry-verification-key")
	if err != nil {
		t.Fatal(err)
	}
	if !readPrivateUsedJSON {
		t.Fatal("expected registry private key to be read via kubectl -o json")
	}
	if !bytes.HasPrefix(published, []byte("-----BEGIN PUBLIC KEY-----")) {
		t.Fatalf("expected PEM public key, got %q", published)
	}
	if bytes.Contains(published, seed) || bytes.Contains(published, []byte(encodedFile)) {
		t.Fatal("registry Secret leaked private signing seed")
	}
	if err := prepared.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureRegistryPublicKeySecretAcceptsRawSeedBytes(t *testing.T) {
	seed := bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	kubernetesData := base64.StdEncoding.EncodeToString(seed)
	created := false

	run := func(_ context.Context, name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(call, "get namespace"):
			return "Active", nil
		case strings.Contains(call, "get secret appliance-keys") && contains(args, "json"):
			payload, _ := json.Marshal(map[string]any{
				"data": map[string]string{"registry_ed25519_private.key": kubernetesData},
			})
			return string(payload), nil
		case strings.Contains(call, "get secret appliance-registry-verification-key"):
			return "", fmt.Errorf("secret not found")
		case strings.Contains(call, "create secret generic appliance-registry-verification-key"):
			created = true
			return "", nil
		case strings.Contains(call, "delete secret"):
			return "", nil
		default:
			return "", fmt.Errorf("unexpected call: %s", call)
		}
	}

	if _, err := helm.EnsureRegistryPublicKeySecret(context.Background(), run, "/kubeconfig",
		"appliance-system", "appliance-keys", "registry", "appliance-registry-verification-key"); err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("expected public verification Secret to be created from raw seed bytes")
	}
}
