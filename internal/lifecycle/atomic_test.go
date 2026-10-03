package lifecycle_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/lifecycle"
)

func TestWriteFileAtomic_CreatesMissingParent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "etc", "rancher", "k3s", "zon-agent-token")
	if err := lifecycle.WriteFileAtomic(path, []byte("K10token\n"), 0o600); err != nil {
		t.Fatalf("write into missing parent: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "K10token\n" {
		t.Fatalf("token = %q", got)
	}
}
