package teardown_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/teardown"
)

type fakeK3s struct {
	stopCalls         int
	stopErr           error
	cleanupCalls      int
	cleanupErr        error
	daemonReloadCalls int
	daemonReloadErr   error
}

func (f *fakeK3s) ops() k3s.Ops {
	return k3s.Ops{
		Stop: func(string) error {
			f.stopCalls++
			return f.stopErr
		},
		CleanupNodeNetwork: func(string, []string) error {
			f.cleanupCalls++
			return f.cleanupErr
		},
		DaemonReload: func() error {
			f.daemonReloadCalls++
			return f.daemonReloadErr
		},
		RemoveKubectlSymlink: k3s.RemoveKubectlSymlink,
	}
}

type installedFiles struct {
	stateDir           string
	binaryPath         string
	configPath         string
	unitPath           string
	kubectlSymlinkPath string
	installedStatePath string
	dataDir            string
	zonctlRealPath     string
	zonctlLauncherPath string
	// Other things stateDir accumulates over normal operation, besides
	// installed-state.json — factory-reset must wipe these too, not just
	// that one file.
	installerLockPath   string
	transactionJSONPath string
	evidenceFilePath    string
	backupFilePath      string
}

func setupInstalledFiles(t *testing.T) installedFiles {
	t.Helper()
	stateDir := t.TempDir()
	f := installedFiles{
		stateDir:            stateDir,
		binaryPath:          filepath.Join(stateDir, "..", "bin", "k3s"),
		configPath:          filepath.Join(stateDir, "..", "k3s", "config.yaml"),
		unitPath:            filepath.Join(stateDir, "..", "systemd", "k3s.service"),
		kubectlSymlinkPath:  filepath.Join(stateDir, "..", "bin", "kubectl"),
		installedStatePath:  filepath.Join(stateDir, "installed-state.json"),
		dataDir:             filepath.Join(stateDir, "..", "k3s-data"),
		zonctlRealPath:      filepath.Join(stateDir, "..", "zonctl-lib", "zonctl-real"),
		zonctlLauncherPath:  filepath.Join(stateDir, "..", "bin", "zonctl"),
		installerLockPath:   filepath.Join(stateDir, "installer.lock"),
		transactionJSONPath: filepath.Join(stateDir, "transaction.json"),
		evidenceFilePath:    filepath.Join(stateDir, "evidence", "evidence-txn-0001.json"),
		backupFilePath:      filepath.Join(stateDir, "backups", "backup-0001", "manifest.json"),
	}

	for _, p := range []string{f.binaryPath, f.configPath, f.unitPath, f.installedStatePath, f.zonctlRealPath, f.zonctlLauncherPath, f.installerLockPath, f.transactionJSONPath, f.evidenceFilePath, f.backupFilePath} {
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("content"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(f.binaryPath, f.kubectlSymlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.dataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dataDir, "state.db"), []byte("appliance data"), 0o640); err != nil {
		t.Fatal(err)
	}
	return f
}

// Data preservation: uninstall must remove K3s and the ownership record
// but must never touch the data directory.
func TestUninstall_PreservesDataDirectory(t *testing.T) {
	f := setupInstalledFiles(t)
	fake := &fakeK3s{}

	checks, err := teardown.Uninstall(context.Background(), fake.ops(), "k3s.service", f.installedStatePath, f.binaryPath, f.configPath, f.unitPath, f.kubectlSymlinkPath, filepath.Join(f.stateDir, "cni", "networks", "cbr0"), []string{"cni0", "flannel.1"})
	if err != nil {
		t.Fatalf("expected uninstall to succeed, got: %v", err)
	}
	if fake.stopCalls != 1 {
		t.Errorf("expected k3s to be stopped exactly once, got %d", fake.stopCalls)
	}
	if fake.cleanupCalls != 1 {
		t.Errorf("expected K3s CNI cleanup exactly once, got %d", fake.cleanupCalls)
	}
	if fake.daemonReloadCalls != 1 {
		t.Errorf("expected systemd daemon-reload exactly once after removing the unit file, got %d", fake.daemonReloadCalls)
	}
	if len(checks) == 0 {
		t.Error("expected evidence checks")
	}

	for _, p := range []string{f.binaryPath, f.configPath, f.unitPath, f.installedStatePath} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected %s to be removed, stat err=%v", p, err)
		}
	}

	data, err := os.ReadFile(filepath.Join(f.dataDir, "state.db"))
	if err != nil {
		t.Fatalf("expected the data directory to survive uninstall: %v", err)
	}
	if string(data) != "appliance data" {
		t.Error("expected data directory contents to be unchanged")
	}
}

// Uninstall must keep zonctl itself in place — you need it on the host
// to reinstall afterward. Only factory-reset removes it.
func TestUninstall_KeepsZonctlBinaries(t *testing.T) {
	f := setupInstalledFiles(t)
	fake := &fakeK3s{}

	if _, err := teardown.Uninstall(context.Background(), fake.ops(), "k3s.service", f.installedStatePath, f.binaryPath, f.configPath, f.unitPath, f.kubectlSymlinkPath, filepath.Join(f.stateDir, "cni", "networks", "cbr0"), []string{"cni0", "flannel.1"}); err != nil {
		t.Fatalf("expected uninstall to succeed, got: %v", err)
	}
	for _, p := range []string{f.zonctlRealPath, f.zonctlLauncherPath} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected %s to survive a plain uninstall, stat err=%v", p, err)
		}
	}
}

// This is the exact incident this test guards against: a stale "kubectl"
// symlink left pointing at a removed k3s binary silently breaks every
// future `kubectl` invocation (zonctl's own included) until the next
// install happens to overwrite it. Uninstall must clean it up itself.
func TestUninstall_RemovesKubectlSymlink(t *testing.T) {
	f := setupInstalledFiles(t)
	fake := &fakeK3s{}

	if _, err := teardown.Uninstall(context.Background(), fake.ops(), "k3s.service", f.installedStatePath, f.binaryPath, f.configPath, f.unitPath, f.kubectlSymlinkPath, filepath.Join(f.stateDir, "cni", "networks", "cbr0"), []string{"cni0", "flannel.1"}); err != nil {
		t.Fatalf("expected uninstall to succeed, got: %v", err)
	}
	if _, err := os.Lstat(f.kubectlSymlinkPath); !os.IsNotExist(err) {
		t.Errorf("expected the kubectl symlink to be removed, stat err=%v", err)
	}
}

func TestUninstall_StopFailurePropagatesAndPreservesFiles(t *testing.T) {
	f := setupInstalledFiles(t)
	fake := &fakeK3s{stopErr: os.ErrPermission}

	if _, err := teardown.Uninstall(context.Background(), fake.ops(), "k3s.service", f.installedStatePath, f.binaryPath, f.configPath, f.unitPath, f.kubectlSymlinkPath, filepath.Join(f.stateDir, "cni", "networks", "cbr0"), []string{"cni0", "flannel.1"}); err == nil {
		t.Fatal("expected a stop failure to fail the uninstall")
	}
	if _, err := os.Stat(f.binaryPath); err != nil {
		t.Error("expected the binary to remain if k3s could not be stopped")
	}
}

// Destructive confirmation, at the package level: factory-reset refuses
// outright without a verified backup or an explicit override.
func TestFactoryReset_RefusesWithoutBackupOrOverride(t *testing.T) {
	f := setupInstalledFiles(t)
	fake := &fakeK3s{}

	if _, err := teardown.FactoryReset(context.Background(), fake.ops(), "k3s.service", f.stateDir, f.binaryPath, f.configPath, f.unitPath, f.kubectlSymlinkPath, filepath.Join(f.stateDir, "cni", "networks", "cbr0"), []string{"cni0", "flannel.1"}, f.dataDir, f.zonctlRealPath, f.zonctlLauncherPath, false, false); err == nil {
		t.Fatal("expected factory-reset to refuse without a verified backup or override")
	}
	if fake.stopCalls != 0 {
		t.Error("expected no k3s mutation when factory-reset refuses")
	}
	if _, err := os.Stat(f.dataDir); err != nil {
		t.Error("expected the data directory to survive a refused factory-reset")
	}
}

func TestFactoryReset_WipesDataWithVerifiedBackup(t *testing.T) {
	f := setupInstalledFiles(t)
	fake := &fakeK3s{}

	if _, err := teardown.FactoryReset(context.Background(), fake.ops(), "k3s.service", f.stateDir, f.binaryPath, f.configPath, f.unitPath, f.kubectlSymlinkPath, filepath.Join(f.stateDir, "cni", "networks", "cbr0"), []string{"cni0", "flannel.1"}, f.dataDir, f.zonctlRealPath, f.zonctlLauncherPath, true, false); err != nil {
		t.Fatalf("expected factory-reset to succeed with a verified backup, got: %v", err)
	}
	if _, err := os.Stat(f.dataDir); !os.IsNotExist(err) {
		t.Errorf("expected the data directory to be removed, stat err=%v", err)
	}
}

func TestFactoryReset_WipesDataWithExplicitOverride(t *testing.T) {
	f := setupInstalledFiles(t)
	fake := &fakeK3s{}

	if _, err := teardown.FactoryReset(context.Background(), fake.ops(), "k3s.service", f.stateDir, f.binaryPath, f.configPath, f.unitPath, f.kubectlSymlinkPath, filepath.Join(f.stateDir, "cni", "networks", "cbr0"), []string{"cni0", "flannel.1"}, f.dataDir, f.zonctlRealPath, f.zonctlLauncherPath, false, true); err != nil {
		t.Fatalf("expected factory-reset to succeed with an explicit override, got: %v", err)
	}
	if _, err := os.Stat(f.dataDir); !os.IsNotExist(err) {
		t.Errorf("expected the data directory to be removed, stat err=%v", err)
	}
}

// This is the exact behavior just added: factory-reset is the one
// operation meant to leave nothing behind, including zonctl itself.
func TestFactoryReset_RemovesZonctlBinaries(t *testing.T) {
	f := setupInstalledFiles(t)
	fake := &fakeK3s{}

	if _, err := teardown.FactoryReset(context.Background(), fake.ops(), "k3s.service", f.stateDir, f.binaryPath, f.configPath, f.unitPath, f.kubectlSymlinkPath, filepath.Join(f.stateDir, "cni", "networks", "cbr0"), []string{"cni0", "flannel.1"}, f.dataDir, f.zonctlRealPath, f.zonctlLauncherPath, false, true); err != nil {
		t.Fatalf("expected factory-reset to succeed, got: %v", err)
	}
	for _, p := range []string{f.zonctlRealPath, f.zonctlLauncherPath} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected %s to be removed by factory-reset, stat err=%v", p, err)
		}
	}
}

// This is the actual gap a real deployment hit: factory-reset only ever
// removed the single installed-state.json file, leaving the installer
// lock, transaction journal, evidence history, and — most importantly —
// zonctl backup's own snapshots of appliance data sitting in stateDir.
// A "factory reset" that leaves old backups on disk defeats the point.
func TestFactoryReset_WipesEntireStateDirNotJustInstalledState(t *testing.T) {
	f := setupInstalledFiles(t)
	fake := &fakeK3s{}

	if _, err := teardown.FactoryReset(context.Background(), fake.ops(), "k3s.service", f.stateDir, f.binaryPath, f.configPath, f.unitPath, f.kubectlSymlinkPath, filepath.Join(f.stateDir, "cni", "networks", "cbr0"), []string{"cni0", "flannel.1"}, f.dataDir, f.zonctlRealPath, f.zonctlLauncherPath, false, true); err != nil {
		t.Fatalf("expected factory-reset to succeed, got: %v", err)
	}
	if _, err := os.Stat(f.stateDir); !os.IsNotExist(err) {
		t.Errorf("expected the entire state directory to be removed, stat err=%v", err)
	}
}
