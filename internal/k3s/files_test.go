package k3s_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
)

func TestWriteConfig_CreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.yaml")
	cfg := k3s.Config{NodeName: "n", DataDir: "/d"}

	if err := k3s.WriteConfig(path, cfg); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != cfg.Render() {
		t.Error("written config does not match rendered content")
	}
}

func TestWriteUnit_CreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "systemd", "k3s.service")
	unit := k3s.UnitConfig{BinaryPath: "/bin/k3s", ConfigPath: "/etc/k3s/config.yaml"}

	if err := k3s.WriteUnit(path, unit); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != unit.Render() {
		t.Error("written unit does not match rendered content")
	}
}

func TestInstallBinary_CopiesAndMarksExecutable(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "k3s-src")
	if err := os.WriteFile(src, []byte("fake k3s binary bytes"), 0o644); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "install", "bin", "k3s")
	if err := k3s.InstallBinary(src, dest); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("expected installed binary to be executable, got mode %s", info.Mode())
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "fake k3s binary bytes" {
		t.Error("installed binary content does not match source")
	}
}

func TestInstallBinary_MissingSourceFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := k3s.InstallBinary(filepath.Join(dir, "missing"), filepath.Join(dir, "dest")); err == nil {
		t.Error("expected missing source binary to fail")
	}
}

func TestEnsureKubectlSymlink_CreatesSymlinkToK3sBinary(t *testing.T) {
	dir := t.TempDir()
	k3sPath := filepath.Join(dir, "k3s")
	kubectlPath := filepath.Join(dir, "kubectl")

	if err := k3s.EnsureKubectlSymlink(k3sPath, kubectlPath); err != nil {
		t.Fatal(err)
	}

	target, err := os.Readlink(kubectlPath)
	if err != nil {
		t.Fatal(err)
	}
	if target != k3sPath {
		t.Errorf("expected symlink to point at %s, got %s", k3sPath, target)
	}
}

// This is the exact scenario that broke `kubectl` on a real appliance: a
// stale symlink (e.g. left over from a previous install/uninstall cycle)
// already occupies kubectlPath. EnsureKubectlSymlink must replace it, not
// silently leave the stale target in place.
func TestEnsureKubectlSymlink_ReplacesStaleSymlink(t *testing.T) {
	dir := t.TempDir()
	oldTarget := filepath.Join(dir, "old-k3s-now-gone")
	k3sPath := filepath.Join(dir, "k3s")
	kubectlPath := filepath.Join(dir, "kubectl")

	if err := os.Symlink(oldTarget, kubectlPath); err != nil {
		t.Fatal(err)
	}

	if err := k3s.EnsureKubectlSymlink(k3sPath, kubectlPath); err != nil {
		t.Fatal(err)
	}

	target, err := os.Readlink(kubectlPath)
	if err != nil {
		t.Fatal(err)
	}
	if target != k3sPath {
		t.Errorf("expected the stale symlink to be replaced with one pointing at %s, got %s", k3sPath, target)
	}
}

func TestRemoveKubectlSymlink_RemovesOnlyIfItPointsAtK3sBinary(t *testing.T) {
	dir := t.TempDir()
	k3sPath := filepath.Join(dir, "k3s")
	kubectlPath := filepath.Join(dir, "kubectl")

	if err := os.Symlink(k3sPath, kubectlPath); err != nil {
		t.Fatal(err)
	}
	if err := k3s.RemoveKubectlSymlink(k3sPath, kubectlPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(kubectlPath); !os.IsNotExist(err) {
		t.Errorf("expected the symlink to be removed, stat err=%v", err)
	}
}

// An operator-managed kubectl (or one pointing somewhere zonctl never
// created) is not this package's to delete.
func TestRemoveKubectlSymlink_LeavesUnrelatedEntryAlone(t *testing.T) {
	dir := t.TempDir()
	k3sPath := filepath.Join(dir, "k3s")
	kubectlPath := filepath.Join(dir, "kubectl")

	if err := os.WriteFile(kubectlPath, []byte("a real, unrelated kubectl binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := k3s.RemoveKubectlSymlink(k3sPath, kubectlPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(kubectlPath); err != nil {
		t.Errorf("expected the unrelated kubectl to survive, stat err=%v", err)
	}
}

func TestRemoveKubectlSymlink_MissingPathIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	if err := k3s.RemoveKubectlSymlink(filepath.Join(dir, "k3s"), filepath.Join(dir, "kubectl")); err != nil {
		t.Errorf("expected a missing kubectl path to be a no-op, got: %v", err)
	}
}
