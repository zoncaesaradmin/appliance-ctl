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

// EnsureKubectlSymlink makes kubectlPath a symlink to k3sBinaryPath. K3s
// is a multicall binary: invoked as "kubectl" it behaves exactly like a
// standalone kubectl. The upstream k3s.io installer creates this
// convenience symlink itself, but only when nothing already exists at
// that path — a stale/dangling symlink left over from an earlier
// install (e.g. after this appliance's own binary was removed and
// reinstalled) silently blocks that recreation, and no operator command
// ever surfaces that as a K3s problem, only a confusing "kubectl:
// command not found". zonctl owns this symlink outright instead of
// hoping K3s's own best-effort logic keeps it consistent: this call is
// always idempotent, replacing anything already at kubectlPath.
func EnsureKubectlSymlink(k3sBinaryPath, kubectlPath string) error {
	if err := os.MkdirAll(filepath.Dir(kubectlPath), 0o755); err != nil {
		return fmt.Errorf("k3s: create kubectl symlink directory: %w", err)
	}
	if err := os.Remove(kubectlPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("k3s: remove existing kubectl entry: %w", err)
	}
	if err := os.Symlink(k3sBinaryPath, kubectlPath); err != nil {
		return fmt.Errorf("k3s: create kubectl symlink: %w", err)
	}
	return nil
}

// RemoveKubectlSymlink removes kubectlPath if it is a symlink pointing
// at k3sBinaryPath — the exact one zonctl created via
// EnsureKubectlSymlink. It leaves any other file/symlink at that path
// alone: an operator-installed system kubectl that predates or
// coexisted with the appliance is not this package's to delete.
func RemoveKubectlSymlink(k3sBinaryPath, kubectlPath string) error {
	target, err := os.Readlink(kubectlPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		// Not a symlink (or unreadable) — not something we created, leave it.
		return nil
	}
	if target != k3sBinaryPath {
		return nil
	}
	if err := os.Remove(kubectlPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("k3s: remove kubectl symlink: %w", err)
	}
	return nil
}
