package zonctlhost

import (
	"fmt"
	"os"
	"path/filepath"
)

// InstallSpec describes where the host-level zonctl binary and launcher
// should be installed.
type InstallSpec struct {
	SourceBinaryPath string
	RealDestPath     string
	LauncherDestPath string
}

// Install copies the bundled zonctl binary into a stable host-managed
// location and writes a launcher into PATH. The launcher automatically
// prepends <bundle-dir>/bin to PATH when --bundle-dir is supplied, so
// install/upgrade can still use bundle-local helm/kubectl/ctr helpers.
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

	rollback := func() error {
		if err := restoreFile(spec.RealDestPath, realPrev); err != nil {
			return err
		}
		return restoreFile(spec.LauncherDestPath, launcherPrev)
	}

	if err := copyExecutable(spec.SourceBinaryPath, spec.RealDestPath); err != nil {
		_ = rollback()
		return nil, err
	}
	if err := writeExecutable(spec.LauncherDestPath, launcherScript(spec.RealDestPath)); err != nil {
		_ = rollback()
		return nil, err
	}

	return rollback, nil
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

func launcherScript(realPath string) []byte {
	return []byte(fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

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

if [[ -n "$BUNDLE_DIR" && -d "$BUNDLE_DIR/bin" ]]; then
  export PATH="$BUNDLE_DIR/bin:$PATH"
fi

exec "%s" "$@"
`, realPath))
}
