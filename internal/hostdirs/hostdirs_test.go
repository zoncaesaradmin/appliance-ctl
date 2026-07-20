package hostdirs_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdirs"
)

type chownCall struct {
	path     string
	uid, gid int
}

func TestEnsureOwnedDir_CreatesMissingDirectoryAndChowns(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "workspaces")
	var calls []chownCall
	fakeChown := func(path string, uid, gid int) error {
		calls = append(calls, chownCall{path, uid, gid})
		return nil
	}

	if err := hostdirs.EnsureOwnedDir(dir, 10001, 10001, 0o770, fakeChown); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("expected directory to be created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("expected a directory")
	}
	if len(calls) != 1 || calls[0] != (chownCall{dir, 10001, 10001}) {
		t.Errorf("expected exactly one chown call for %s to 10001:10001, got %v", dir, calls)
	}
}

// This is the exact production incident this package exists to prevent:
// a directory that already existed with the wrong owner (e.g. created by
// kubelet's hostPath DirectoryOrCreate as root, before this fix shipped)
// must have its ownership and mode corrected, not left alone because it
// already exists.
func TestEnsureOwnedDir_FixesModeOnPreExistingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "workspaces")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	var calls []chownCall
	fakeChown := func(path string, uid, gid int) error {
		calls = append(calls, chownCall{path, uid, gid})
		return nil
	}

	if err := hostdirs.EnsureOwnedDir(dir, 10001, 10001, 0o770, fakeChown); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o770 {
		t.Errorf("expected mode to be corrected to 0770, got %o", info.Mode().Perm())
	}
	if len(calls) != 1 || calls[0] != (chownCall{dir, 10001, 10001}) {
		t.Errorf("expected chown to still run on a pre-existing directory, got %v", calls)
	}
}

func TestEnsureOwnedDir_PropagatesChownFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "workspaces")
	failingChown := func(string, int, int) error {
		return errors.New("operation not permitted")
	}

	if err := hostdirs.EnsureOwnedDir(dir, 10001, 10001, 0o770, failingChown); err == nil {
		t.Fatal("expected chown failure to propagate")
	}
}
