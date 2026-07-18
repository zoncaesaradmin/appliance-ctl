package k3s_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
)

func TestCleanupNodeNetwork_RemovesCNILeaseFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cni", "networks", "cbr0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"10.42.0.10", "last_reserved_ip.0", "lock"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := k3s.CleanupNodeNetwork(dir, nil); err != nil {
		t.Fatalf("CleanupNodeNetwork: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected empty CNI network dir, found %d entries", len(entries))
	}
}
