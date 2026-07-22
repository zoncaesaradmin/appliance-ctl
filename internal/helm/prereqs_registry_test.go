package helm_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
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
	var readPrivatePath string

	run := func(_ context.Context, name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(call, "get namespace"):
			return "Active", nil
		case strings.Contains(call, "registry_ed25519_private.key"):
			for _, arg := range args {
				if strings.HasPrefix(arg, "jsonpath=") {
					readPrivatePath = arg
				}
			}
			return kubernetesData, nil
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
	if want := "jsonpath={.data['registry_ed25519_private.key']}"; readPrivatePath != want {
		t.Fatalf("secret jsonpath = %q, want %q", readPrivatePath, want)
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
