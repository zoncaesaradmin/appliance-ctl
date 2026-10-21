package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestExecToFileStreamsToProtectedAtomicDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "artifact.dump")
	if err := ExecToFile(context.Background(), path, "sh", "-c", "printf recovery-set"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "recovery-set" {
		t.Fatalf("artifact = %q, %v", data, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v; want 0600", info.Mode(), err)
	}
}
