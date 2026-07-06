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
	stopCalls int
	stopErr   error
}

func (f *fakeK3s) ops() k3s.Ops {
	return k3s.Ops{
		Stop: func(string) error {
			f.stopCalls++
			return f.stopErr
		},
	}
}

func setupInstalledFiles(t *testing.T) (stateDir string, binaryPath, configPath, unitPath, installedStatePath, dataDir string) {
	t.Helper()
	stateDir = t.TempDir()
	binaryPath = filepath.Join(stateDir, "bin", "k3s")
	configPath = filepath.Join(stateDir, "k3s", "config.yaml")
	unitPath = filepath.Join(stateDir, "systemd", "k3s.service")
	installedStatePath = filepath.Join(stateDir, "installed-state.json")
	dataDir = filepath.Join(stateDir, "k3s-data")

	for _, p := range []string{binaryPath, configPath, unitPath, installedStatePath} {
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("content"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "state.db"), []byte("appliance data"), 0o640); err != nil {
		t.Fatal(err)
	}
	return stateDir, binaryPath, configPath, unitPath, installedStatePath, dataDir
}

// Data preservation: uninstall must remove K3s and the ownership record
// but must never touch the data directory.
func TestUninstall_PreservesDataDirectory(t *testing.T) {
	_, binaryPath, configPath, unitPath, installedStatePath, dataDir := setupInstalledFiles(t)
	fake := &fakeK3s{}

	checks, err := teardown.Uninstall(context.Background(), fake.ops(), "k3s.service", installedStatePath, binaryPath, configPath, unitPath)
	if err != nil {
		t.Fatalf("expected uninstall to succeed, got: %v", err)
	}
	if fake.stopCalls != 1 {
		t.Errorf("expected k3s to be stopped exactly once, got %d", fake.stopCalls)
	}
	if len(checks) == 0 {
		t.Error("expected evidence checks")
	}

	for _, p := range []string{binaryPath, configPath, unitPath, installedStatePath} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected %s to be removed, stat err=%v", p, err)
		}
	}

	data, err := os.ReadFile(filepath.Join(dataDir, "state.db"))
	if err != nil {
		t.Fatalf("expected the data directory to survive uninstall: %v", err)
	}
	if string(data) != "appliance data" {
		t.Error("expected data directory contents to be unchanged")
	}
}

func TestUninstall_StopFailurePropagatesAndPreservesFiles(t *testing.T) {
	_, binaryPath, configPath, unitPath, installedStatePath, _ := setupInstalledFiles(t)
	fake := &fakeK3s{stopErr: os.ErrPermission}

	if _, err := teardown.Uninstall(context.Background(), fake.ops(), "k3s.service", installedStatePath, binaryPath, configPath, unitPath); err == nil {
		t.Fatal("expected a stop failure to fail the uninstall")
	}
	if _, err := os.Stat(binaryPath); err != nil {
		t.Error("expected the binary to remain if k3s could not be stopped")
	}
}

// Destructive confirmation, at the package level: factory-reset refuses
// outright without a verified backup or an explicit override.
func TestFactoryReset_RefusesWithoutBackupOrOverride(t *testing.T) {
	_, binaryPath, configPath, unitPath, installedStatePath, dataDir := setupInstalledFiles(t)
	fake := &fakeK3s{}

	if _, err := teardown.FactoryReset(context.Background(), fake.ops(), "k3s.service", installedStatePath, binaryPath, configPath, unitPath, dataDir, false, false); err == nil {
		t.Fatal("expected factory-reset to refuse without a verified backup or override")
	}
	if fake.stopCalls != 0 {
		t.Error("expected no k3s mutation when factory-reset refuses")
	}
	if _, err := os.Stat(dataDir); err != nil {
		t.Error("expected the data directory to survive a refused factory-reset")
	}
}

func TestFactoryReset_WipesDataWithVerifiedBackup(t *testing.T) {
	_, binaryPath, configPath, unitPath, installedStatePath, dataDir := setupInstalledFiles(t)
	fake := &fakeK3s{}

	if _, err := teardown.FactoryReset(context.Background(), fake.ops(), "k3s.service", installedStatePath, binaryPath, configPath, unitPath, dataDir, true, false); err != nil {
		t.Fatalf("expected factory-reset to succeed with a verified backup, got: %v", err)
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Errorf("expected the data directory to be removed, stat err=%v", err)
	}
}

func TestFactoryReset_WipesDataWithExplicitOverride(t *testing.T) {
	_, binaryPath, configPath, unitPath, installedStatePath, dataDir := setupInstalledFiles(t)
	fake := &fakeK3s{}

	if _, err := teardown.FactoryReset(context.Background(), fake.ops(), "k3s.service", installedStatePath, binaryPath, configPath, unitPath, dataDir, false, true); err != nil {
		t.Fatalf("expected factory-reset to succeed with an explicit override, got: %v", err)
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Errorf("expected the data directory to be removed, stat err=%v", err)
	}
}
