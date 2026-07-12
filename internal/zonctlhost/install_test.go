package zonctlhost_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/zonctlhost"
)

func TestInstallWritesRealBinaryAndLauncher(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source-zonctl")
	if err := os.WriteFile(src, []byte("zonctl-binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	realDest := filepath.Join(dir, "usr-local-lib", "zon", "bin", "zonctl-real")
	launcherDest := filepath.Join(dir, "usr-local-bin", "zonctl")

	rollback, err := zonctlhost.Install(zonctlhost.InstallSpec{
		SourceBinaryPath: src,
		RealDestPath:     realDest,
		LauncherDestPath: launcherDest,
	})
	if err != nil {
		t.Fatalf("expected install to succeed, got: %v", err)
	}
	t.Cleanup(func() {
		_ = rollback()
	})

	realData, err := os.ReadFile(realDest)
	if err != nil {
		t.Fatal(err)
	}
	if string(realData) != "zonctl-binary" {
		t.Fatalf("expected installed binary contents to match source, got %q", string(realData))
	}

	launcherData, err := os.ReadFile(launcherDest)
	if err != nil {
		t.Fatal(err)
	}
	launcher := string(launcherData)
	if !strings.Contains(launcher, realDest) {
		t.Fatalf("expected launcher to exec %s, got %s", realDest, launcher)
	}
	if !strings.Contains(launcher, `--bundle-dir`) {
		t.Fatalf("expected launcher to handle --bundle-dir, got %s", launcher)
	}
}

func TestInstallRollbackRestoresPreviousFiles(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source-zonctl")
	if err := os.WriteFile(src, []byte("new-binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	realDest := filepath.Join(dir, "usr-local-lib", "zon", "bin", "zonctl-real")
	launcherDest := filepath.Join(dir, "usr-local-bin", "zonctl")
	if err := os.MkdirAll(filepath.Dir(realDest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(launcherDest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realDest, []byte("old-real"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcherDest, []byte("old-launcher"), 0o744); err != nil {
		t.Fatal(err)
	}

	rollback, err := zonctlhost.Install(zonctlhost.InstallSpec{
		SourceBinaryPath: src,
		RealDestPath:     realDest,
		LauncherDestPath: launcherDest,
	})
	if err != nil {
		t.Fatalf("expected install to succeed, got: %v", err)
	}
	if err := rollback(); err != nil {
		t.Fatalf("expected rollback to succeed, got: %v", err)
	}

	realData, err := os.ReadFile(realDest)
	if err != nil {
		t.Fatal(err)
	}
	if string(realData) != "old-real" {
		t.Fatalf("expected old real binary to be restored, got %q", string(realData))
	}

	launcherData, err := os.ReadFile(launcherDest)
	if err != nil {
		t.Fatal(err)
	}
	if string(launcherData) != "old-launcher" {
		t.Fatalf("expected old launcher to be restored, got %q", string(launcherData))
	}
}

func TestUninstall_RemovesBothFiles(t *testing.T) {
	dir := t.TempDir()
	realDest := filepath.Join(dir, "usr-local-lib", "zon", "bin", "zonctl-real")
	launcherDest := filepath.Join(dir, "usr-local-bin", "zonctl")
	if err := os.MkdirAll(filepath.Dir(realDest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(launcherDest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realDest, []byte("zonctl-real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcherDest, []byte("launcher"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := zonctlhost.Uninstall(realDest, launcherDest); err != nil {
		t.Fatalf("expected uninstall to succeed, got: %v", err)
	}

	for _, p := range []string{realDest, launcherDest} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected %s to be removed, stat err=%v", p, err)
		}
	}
}

func TestUninstall_MissingFilesAreNotAnError(t *testing.T) {
	dir := t.TempDir()
	realDest := filepath.Join(dir, "zonctl-real")
	launcherDest := filepath.Join(dir, "zonctl")

	if err := zonctlhost.Uninstall(realDest, launcherDest); err != nil {
		t.Errorf("expected missing files to be a no-op, got: %v", err)
	}
}
