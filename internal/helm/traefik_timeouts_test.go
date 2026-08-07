package helm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
)

func TestEnsureTraefikTransferTimeoutsAppliesManifest(t *testing.T) {
	var gotArgs []string
	run := func(ctx context.Context, name string, args ...string) (string, error) {
		if name != "kubectl" {
			t.Fatalf("unexpected binary %q", name)
		}
		gotArgs = append([]string{name}, args...)
		for i, a := range args {
			if a == "-f" && i+1 < len(args) {
				body, err := os.ReadFile(args[i+1])
				if err != nil {
					t.Fatalf("read applied manifest: %v", err)
				}
				text := string(body)
				for _, want := range []string{
					"kind: HelmChartConfig",
					"name: traefik",
					"writeTimeout: 30m",
					"readTimeout: 30m",
					"websecure:",
				} {
					if !strings.Contains(text, want) {
						t.Fatalf("manifest missing %q:\n%s", want, text)
					}
				}
			}
		}
		return "helmchartconfig.helm.cattle.io/traefik configured", nil
	}

	check, err := EnsureTraefikTransferTimeouts(context.Background(), run, "/tmp/kubeconfig")
	if err != nil {
		t.Fatalf("EnsureTraefikTransferTimeouts: %v", err)
	}
	if check.Status != evidence.StatusPass {
		t.Fatalf("status = %q message = %q", check.Status, check.Message)
	}
	joined := strings.Join(gotArgs, " ")
	if !strings.Contains(joined, "apply") || !strings.Contains(joined, "--kubeconfig /tmp/kubeconfig") {
		t.Fatalf("unexpected kubectl invocation: %v", gotArgs)
	}
	for i, a := range gotArgs {
		if a == "-f" && i+1 < len(gotArgs) {
			if _, err := os.Stat(gotArgs[i+1]); !os.IsNotExist(err) {
				t.Fatalf("expected temp manifest removed, stat err=%v path=%s", err, gotArgs[i+1])
			}
			if filepath.Base(gotArgs[i+1]) == "." || gotArgs[i+1] == "" {
				t.Fatal("empty apply path")
			}
		}
	}
}

func TestEnsureTraefikTransferTimeoutsNilRunner(t *testing.T) {
	check, err := EnsureTraefikTransferTimeouts(context.Background(), nil, "/tmp/kubeconfig")
	if err == nil {
		t.Fatal("expected error for nil runner")
	}
	if check.Status != evidence.StatusFail {
		t.Fatalf("status = %q, want fail", check.Status)
	}
}
