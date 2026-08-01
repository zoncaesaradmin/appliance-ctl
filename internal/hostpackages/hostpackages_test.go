package hostpackages

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePackageDir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "ubuntu", "24.04", "amd64")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	resolved, err := ResolvePackageDir(root, "ubuntu", "24.04", "amd64")
	if err != nil {
		t.Fatalf("expected package dir to resolve, got: %v", err)
	}
	if resolved != dir {
		t.Fatalf("ResolvePackageDir = %q, want %q", resolved, dir)
	}
}

func TestDebArchivesSortsMatchingDebs(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "b.deb"), []byte("b"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.deb"), []byte("a"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.txt"), []byte("ignore"), 0o640); err != nil {
		t.Fatal(err)
	}

	debs, err := debArchives(root)
	if err != nil {
		t.Fatalf("expected deb listing to succeed, got: %v", err)
	}
	if len(debs) != 2 {
		t.Fatalf("expected 2 deb archives, got %d", len(debs))
	}
	if filepath.Base(debs[0]) != "a.deb" || filepath.Base(debs[1]) != "b.deb" {
		t.Fatalf("unexpected deb order: %v", debs)
	}
}
