package k3s

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/zoncaesaradmin/appliance-ctl/internal/lifecycle"
)

// WriteConfig atomically writes cfg's rendered content to path.
func WriteConfig(path string, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("k3s: create config directory: %w", err)
	}
	return lifecycle.WriteFileAtomic(path, []byte(cfg.Render()), 0o640)
}

// WriteUnit atomically writes unit's rendered content to path.
func WriteUnit(path string, unit UnitConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("k3s: create unit directory: %w", err)
	}
	return lifecycle.WriteFileAtomic(path, []byte(unit.Render()), 0o644)
}

// InstallBinary copies the K3s binary from the bundle into its install
// path and marks it executable. Digest and signature verification
// (internal/verify) happens before this call; this step only places
// bytes already proven authentic, and does so atomically so a crash
// mid-copy never leaves a partially written binary at destPath.
func InstallBinary(srcPath, destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("k3s: create binary directory: %w", err)
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("k3s: open source binary %s: %w", srcPath, err)
	}
	defer src.Close()

	tmp, err := os.CreateTemp(filepath.Dir(destPath), ".tmp-k3s-*")
	if err != nil {
		return fmt.Errorf("k3s: create temp binary: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return fmt.Errorf("k3s: copy binary: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("k3s: sync binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("k3s: close temp binary: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return fmt.Errorf("k3s: chmod binary: %w", err)
	}
	return os.Rename(tmpPath, destPath)
}
