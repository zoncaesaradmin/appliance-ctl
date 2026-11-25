package helm_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/helm"
)

func TestEnsureApplicationIdentitySecretCreatesInternalKey(t *testing.T) {
	var createCall string
	run := func(_ context.Context, name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(call, "get secret application-identity-secrets"):
			return "", fmt.Errorf("secret not found")
		case strings.Contains(call, "create secret generic application-identity-secrets"):
			createCall = call
			return "", nil
		case strings.Contains(call, "delete secret application-identity-secrets"):
			return "", nil
		default:
			return "", fmt.Errorf("unexpected call: %s", call)
		}
	}
	prepared, err := helm.EnsureApplicationIdentitySecret(context.Background(), run, "/kubeconfig", "ace-apps", "application-identity-secrets")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(createCall, "--from-file=internal-key=") {
		t.Fatalf("internal key was not created: %s", createCall)
	}
	if !strings.Contains(createCall, "--from-file=delivery-key=") {
		t.Fatalf("delivery key was not created: %s", createCall)
	}
	if err := prepared.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureApplicationIdentitySecretUpgradesWithoutReplacingExistingKeys(t *testing.T) {
	otp := base64.StdEncoding.EncodeToString([]byte("otp-material"))
	rate := base64.StdEncoding.EncodeToString([]byte("rate-material"))
	payload, _ := json.Marshal(map[string]any{"data": map[string]string{"otp-key": otp, "rate-key": rate}})
	var applied []byte
	run := func(_ context.Context, name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(call, "get secret application-identity-secrets"):
			return string(payload), nil
		case contains(args, "apply") && contains(args, "-f"):
			for _, arg := range args {
				if arg == "-f" {
					continue
				}
				if strings.HasSuffix(arg, ".json") {
					var err error
					applied, err = os.ReadFile(arg)
					return "", err
				}
			}
			return "", fmt.Errorf("missing apply manifest")
		default:
			return "", fmt.Errorf("unexpected call: %s", call)
		}
	}
	if _, err := helm.EnsureApplicationIdentitySecret(context.Background(), run, "/kubeconfig", "ace-apps", "application-identity-secrets"); err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(applied, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Data["otp-key"] != otp || manifest.Data["rate-key"] != rate || manifest.Data["internal-key"] == "" || manifest.Data["delivery-key"] == "" {
		t.Fatalf("existing keys were not preserved during upgrade: %#v", manifest.Data)
	}
}
