package helm_test

import (
	"context"
	"testing"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/helm"
)

func TestCollectFailureDiagnostics_SatisfiesEvidenceSchema(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) (string, error) {
		return name + " diagnostic output", nil
	}

	checks := helm.CollectFailureDiagnostics(context.Background(), run, "kubeconfig", helm.ChartRelease{
		Name:      "zon",
		Namespace: "zon",
	})
	if len(checks) == 0 {
		t.Fatal("expected non-empty diagnostics checks")
	}
	for _, check := range checks {
		if check.Status != evidence.StatusOperatorAction {
			t.Fatalf("expected operator-action status, got %s", check.Status)
		}
		if check.Remediation == "" {
			t.Fatal("expected remediation on diagnostic check")
		}
	}

	if _, err := evidence.BuildReport("install", "0.1.0", "evidence-test-diagnostics", checks, time.Now()); err != nil {
		t.Fatalf("expected diagnostics checks to satisfy evidence schema, got: %v", err)
	}
}
