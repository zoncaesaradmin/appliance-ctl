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
