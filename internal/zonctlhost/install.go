package zonctlhost

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ManagedHelperNames are bundle bin/ tools copied next to zonctl-real on
// install/upgrade so day-2 commands (status, verify, repair) work without
// the temporary extracted bundle on PATH. helm is required because chart
// health checks shell out to it.
var ManagedHelperNames = []string{"helm"}

// InstallSpec describes where the host-level zonctl binary, launcher, and
// durable helpers should be installed.
type InstallSpec struct {
	SourceBinaryPath string
	RealDestPath     string
	LauncherDestPath string
	// HelperSourcePaths are executables copied into filepath.Dir(RealDestPath).
	// Empty is allowed only for tests that intentionally skip helpers; production
	// install/upgrade always pass the managed helpers from the bundle.
	HelperSourcePaths []string
}

// Install copies the bundled zonctl binary into a stable host-managed
// location, installs durable helpers beside it, and writes a launcher into
// PATH. The launcher always prepends the helper directory so status/verify
// find helm after the temporary bundle extract is gone. When --bundle-dir is
// supplied, that bundle's bin/ is prepended first for install/upgrade.
func Install(spec InstallSpec) (func() error, error) {
	if spec.SourceBinaryPath == "" || spec.RealDestPath == "" || spec.LauncherDestPath == "" {
		return nil, fmt.Errorf("zonctlhost: sourceBinaryPath, realDestPath, and launcherDestPath are required")
	}

	realPrev, err := backupFile(spec.RealDestPath)
	if err != nil {
		return nil, err
	}
	launcherPrev, err := backupFile(spec.LauncherDestPath)
	if err != nil {
		return nil, err
	}

	helperDestDir := filepath.Dir(spec.RealDestPath)
	type helperBackup struct {
		dest string
		prev *fileBackup
	}
	var helperBackups []helperBackup
	for _, src := range spec.HelperSourcePaths {
		if strings.TrimSpace(src) == "" {
			continue
		}
		dest := filepath.Join(helperDestDir, filepath.Base(src))
		prev, backupErr := backupFile(dest)
		if backupErr != nil {
			return nil, backupErr
		}
		helperBackups = append(helperBackups, helperBackup{dest: dest, prev: prev})
	}

	rollback := func() error {
		var errs []error
		for i := len(helperBackups) - 1; i >= 0; i-- {
			hb := helperBackups[i]
			if err := restoreFile(hb.dest, hb.prev); err != nil {
				errs = append(errs, err)
			}
		}
		if err := restoreFile(spec.RealDestPath, realPrev); err != nil {
			errs = append(errs, err)
		}
		if err := restoreFile(spec.LauncherDestPath, launcherPrev); err != nil {
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}

	if err := copyExecutable(spec.SourceBinaryPath, spec.RealDestPath); err != nil {
		_ = rollback()
		return nil, err
	}
	for _, src := range spec.HelperSourcePaths {
		if strings.TrimSpace(src) == "" {
			continue
		}
		dest := filepath.Join(helperDestDir, filepath.Base(src))
		if err := copyExecutable(src, dest); err != nil {
			_ = rollback()
			return nil, err
		}
	}
	if err := writeExecutable(spec.LauncherDestPath, launcherScript(spec.RealDestPath, helperDestDir)); err != nil {
		_ = rollback()
		return nil, err
	}

	return rollback, nil
}

// ResolveHelperSourcePaths returns the managed helper binaries from a
// bundle bin directory. Every ManagedHelperNames entry must exist.
func ResolveHelperSourcePaths(bundleBinDir string) ([]string, error) {
	bundleBinDir = strings.TrimSpace(bundleBinDir)
	if bundleBinDir == "" {
		return nil, fmt.Errorf("zonctlhost: bundle bin directory is required")
	}
	paths := make([]string, 0, len(ManagedHelperNames))
	for _, name := range ManagedHelperNames {
		p := filepath.Join(bundleBinDir, name)
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("zonctlhost: bundle missing required helper %q at %s: %w", name, p, err)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("zonctlhost: bundle helper %q at %s is a directory", name, p)
		}
		paths = append(paths, p)
	}
	return paths, nil
}

// Uninstall removes the launcher, real binary, and managed helpers this
// appliance installed. It is meant only for a deliberate, total teardown
// (factory-reset) — routine uninstall keeps zonctl in place so the host
// can be reinstalled with the same command that removed it.
//
// It is safe to call from the very process it's deleting: on Linux,
// removing an executable's directory entry only unlinks the name — the
// kernel keeps the already-open inode (and the running process built
// from it) alive until every reference, including the process's own
// mapped executable, is gone. realDestPath is what's actually running
// (the launcher at launcherDestPath just execs into it); both are safe
// to remove in either order.
func Uninstall(realDestPath, launcherDestPath string) error {
	paths := []string{launcherDestPath, realDestPath}
	if dir := filepath.Dir(realDestPath); dir != "" && dir != "." {
		for _, name := range ManagedHelperNames {
			paths = append(paths, filepath.Join(dir, name))
		}
	}
	var errs []error
	for _, path := range paths {
		if path == "" {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("zonctlhost: remove %s: %w", path, err))
		}
	}
	return errors.Join(errs...)
}

type fileBackup struct {
	exists bool
	mode   os.FileMode
	data   []byte
}

func backupFile(path string) (*fileBackup, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return &fileBackup{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("zonctlhost: stat %s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("zonctlhost: read %s: %w", path, err)
	}
	return &fileBackup{exists: true, mode: info.Mode(), data: data}, nil
}

func restoreFile(path string, backup *fileBackup) error {
	if backup == nil || !backup.exists {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("zonctlhost: remove %s: %w", path, err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("zonctlhost: create parent for %s: %w", path, err)
	}
	if err := os.WriteFile(path, backup.data, backup.mode); err != nil {
		return fmt.Errorf("zonctlhost: restore %s: %w", path, err)
	}
	return nil
}

func copyExecutable(src, dest string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("zonctlhost: read %s: %w", src, err)
	}
	return writeExecutable(dest, data)
}

func writeExecutable(dest string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("zonctlhost: create parent for %s: %w", dest, err)
	}
	if err := os.WriteFile(dest, data, 0o755); err != nil {
		return fmt.Errorf("zonctlhost: write %s: %w", dest, err)
	}
	return nil
}

func launcherScript(realPath, helperDir string) []byte {
	return []byte(fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

# Durable host helpers (helm, …) installed next to zonctl-real.
export PATH=%q:"${PATH:-}"

BUNDLE_DIR=""
PREV=""
for ARG in "$@"; do
  if [[ "$PREV" == "--bundle-dir" ]]; then
    BUNDLE_DIR="$ARG"
    break
  fi
  case "$ARG" in
    --bundle-dir=*)
      BUNDLE_DIR="${ARG#--bundle-dir=}"
      break
      ;;
  esac
  PREV="$ARG"
done

# During install/upgrade, prefer the active bundle bin over the previously
# installed helpers so the run uses the binaries from this release.
if [[ -n "$BUNDLE_DIR" && -d "$BUNDLE_DIR/bin" ]]; then
  export PATH="$BUNDLE_DIR/bin:$PATH"
fi

exec %q "$@"
`, helperDir, realPath))
}
