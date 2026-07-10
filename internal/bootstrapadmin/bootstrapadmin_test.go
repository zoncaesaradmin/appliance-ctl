package bootstrapadmin_test

import (
	"context"
	"testing"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/bootstrapadmin"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
)

// The evidence check Init returns must itself satisfy evidence.v1's
// schema — in particular its Category, which is a fixed enum, not a
// free-form string. Building a real report through evidence.BuildReport
// (which validates against the real schema) catches this class of bug,
// where a single invalid field fails the whole report, not just this
// check.
func TestInit_ReturnedCheckSatisfiesEvidenceSchema(t *testing.T) {
	run := func(context.Context, []byte, string, ...string) (string, error) {
		return "", nil
	}

	check, err := bootstrapadmin.Init(context.Background(), bootstrapadmin.Options{
		Run:           run,
		Kubeconfig:    "/etc/rancher/k3s/k3s.yaml",
		Namespace:     "zon",
		ReleaseName:   "zon",
		AdminUsername: "admin",
		AdminPassword: []byte("a-fully-valid-password"),
	})
	if err != nil {
		t.Fatalf("expected Init to succeed with a working runner, got: %v", err)
	}

	if _, buildErr := evidence.BuildReport("install", "0.1.0", "evidence-test", []evidence.Check{check}, time.Now()); buildErr != nil {
		t.Fatalf("expected the returned check to satisfy the evidence.v1 schema, got: %v", buildErr)
	}
}
