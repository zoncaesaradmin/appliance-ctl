package helm_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/helm"
)

func fakeHelmStatus(out string, err error) func(context.Context, string, ...string) (string, error) {
	return func(_ context.Context, name string, args ...string) (string, error) {
		if name != "helm" || !contains(args, "status") {
			return "", errors.New("unexpected invocation")
		}
		return out, err
	}
}

func TestCheckReleaseHealth_Deployed(t *testing.T) {
	out := `{"info":{"status":"deployed"}}`
	healthy, msg, err := helm.CheckReleaseHealth(context.Background(), fakeHelmStatus(out, nil), "/etc/rancher/k3s/k3s.yaml", "zon", "zon")
	if err != nil {
		t.Fatal(err)
	}
	if !healthy {
		t.Errorf("expected healthy, got message %q", msg)
	}
}

func TestCheckReleaseHealth_NotDeployed(t *testing.T) {
	out := `{"info":{"status":"failed"}}`
	healthy, msg, err := helm.CheckReleaseHealth(context.Background(), fakeHelmStatus(out, nil), "/etc/rancher/k3s/k3s.yaml", "zon", "zon")
	if err != nil {
		t.Fatal(err)
	}
	if healthy {
		t.Error("expected unhealthy for a non-deployed release status")
	}
	if !strings.Contains(msg, "failed") {
		t.Errorf("expected message to mention the actual status, got %q", msg)
	}
}

// The scenario that motivated this check: the release was never
// installed (or was fully removed), so `helm status` reports "not
// found" rather than an error running helm itself. That must surface as
// a reportable unhealthy finding, not a command error.
func TestCheckReleaseHealth_ReleaseMissing(t *testing.T) {
	healthy, msg, err := helm.CheckReleaseHealth(context.Background(), fakeHelmStatus("", errors.New("release: not found")), "/etc/rancher/k3s/k3s.yaml", "zon", "zon")
	if err != nil {
		t.Fatal(err)
	}
	if healthy {
		t.Error("expected unhealthy for a missing release")
	}
	if !strings.Contains(msg, "not found") {
		t.Errorf("expected message to mention the release is not found, got %q", msg)
	}
}

func TestCheckReleaseHealth_PropagatesHelmFailure(t *testing.T) {
	_, _, err := helm.CheckReleaseHealth(context.Background(), fakeHelmStatus("", errors.New("connection refused")), "/etc/rancher/k3s/k3s.yaml", "zon", "zon")
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("expected the helm failure to propagate, got: %v", err)
	}
}
