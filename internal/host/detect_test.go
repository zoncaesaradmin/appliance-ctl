package host_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/host"
)

func TestDetectDoesNotError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "appliance-data")

	facts, err := host.Detect(host.Options{
		DataDir:       dir,
		RequiredPorts: []int{0}, // port 0 asks the OS for a free ephemeral port; never "in use"
	})
	if err != nil {
		t.Fatalf("Detect returned an error: %v", err)
	}

	if facts.Arch == "" {
		t.Error("expected Arch to be populated")
	}
	if facts.Hostname == "" {
		t.Error("expected Hostname to be populated")
	}
	if facts.CPUCount <= 0 {
		t.Error("expected CPUCount to be positive")
	}
	if facts.PortsInUse == nil {
		t.Error("expected PortsInUse to be initialized, not nil")
	}

	if _, err := os.Stat(dir); err != nil {
		t.Logf("data dir not created on this platform, which is fine for the !linux fallback: %v", err)
	}
}
