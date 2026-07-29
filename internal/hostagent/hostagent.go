package hostagent

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/lifecycle"
)

type InstallSpec struct {
	SourceBinaryPath string
	BinaryDestPath   string
	UnitPath         string
	UnitName         string
	SocketPath       string
	LogPath          string
}

type UnitConfig struct {
	BinaryPath string
	SocketPath string
	LogPath    string
}

const unitTemplate = `[Unit]
Description=Zon appliance host agent daemon (release-owned; do not edit)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s --socket-path %s --log-path %s
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
`

func (u UnitConfig) Render() string {
	return fmt.Sprintf(unitTemplate, u.BinaryPath, u.SocketPath, u.LogPath)
}

func WriteUnit(path string, unit UnitConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("hostagent: create unit directory: %w", err)
	}
	return lifecycle.WriteFileAtomic(path, []byte(unit.Render()), 0o644)
}

func InstallBinary(srcPath, destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("hostagent: create binary directory: %w", err)
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("hostagent: open source binary %s: %w", srcPath, err)
	}
	defer src.Close()

	tmp, err := os.CreateTemp(filepath.Dir(destPath), ".tmp-hostagent-*")
	if err != nil {
		return fmt.Errorf("hostagent: create temp binary: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return fmt.Errorf("hostagent: copy binary: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("hostagent: sync binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("hostagent: close temp binary: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return fmt.Errorf("hostagent: chmod binary: %w", err)
	}
	return os.Rename(tmpPath, destPath)
}

func InstallOrUpdate(spec InstallSpec) (func() error, error) {
	if strings.TrimSpace(spec.SourceBinaryPath) == "" || strings.TrimSpace(spec.BinaryDestPath) == "" || strings.TrimSpace(spec.UnitPath) == "" || strings.TrimSpace(spec.UnitName) == "" {
		return nil, fmt.Errorf("hostagent: sourceBinaryPath, binaryDestPath, unitPath, and unitName are required")
	}
	binaryPrev, err := backupFile(spec.BinaryDestPath)
	if err != nil {
		return nil, err
	}
	unitPrev, err := backupFile(spec.UnitPath)
	if err != nil {
		return nil, err
	}

	rollback := func() error {
		var errs []error
		if err := restoreFile(spec.BinaryDestPath, binaryPrev); err != nil {
			errs = append(errs, err)
		}
		if err := restoreFile(spec.UnitPath, unitPrev); err != nil {
			errs = append(errs, err)
		}
		if err := daemonReload(); err != nil {
			errs = append(errs, err)
		}
		if unitPrev.exists {
			if err := enable(spec.UnitName); err != nil {
				errs = append(errs, err)
			} else if err := restart(spec.UnitName); err != nil {
				errs = append(errs, err)
			}
		} else {
			if err := disableAndStop(spec.UnitName); err != nil {
				errs = append(errs, err)
			}
		}
		return joinErrors(errs)
	}

	if err := InstallBinary(spec.SourceBinaryPath, spec.BinaryDestPath); err != nil {
		return nil, err
	}
	if err := WriteUnit(spec.UnitPath, UnitConfig{
		BinaryPath: spec.BinaryDestPath,
		SocketPath: spec.SocketPath,
		LogPath:    spec.LogPath,
	}); err != nil {
		_ = rollback()
		return nil, err
	}
	if err := daemonReload(); err != nil {
		_ = rollback()
		return nil, err
	}
	if err := enable(spec.UnitName); err != nil {
		_ = rollback()
		return nil, err
	}
	if err := restart(spec.UnitName); err != nil {
		_ = rollback()
		return nil, err
	}
	return rollback, nil
}

func Uninstall(spec InstallSpec) error {
	var errs []error
	if err := disableAndStop(spec.UnitName); err != nil {
		errs = append(errs, err)
	}
	for _, path := range []string{spec.UnitPath, spec.BinaryDestPath} {
		if path == "" {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("hostagent: remove %s: %w", path, err))
		}
	}
	if err := daemonReload(); err != nil {
		errs = append(errs, err)
	}
	return joinErrors(errs)
}

func daemonReload() error           { return runSystemctl("daemon-reload") }
func enable(unitName string) error  { return runSystemctl("enable", unitName) }
func restart(unitName string) error { return runSystemctl("restart", unitName) }

func disableAndStop(unitName string) error {
	var errs []error
	if err := runSystemctl("disable", unitName); err != nil && !isMissingUnitError(err) {
		errs = append(errs, err)
	}
	if err := runSystemctl("stop", unitName); err != nil && !isMissingUnitError(err) {
		errs = append(errs, err)
	}
	return joinErrors(errs)
}

func runSystemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("hostagent: systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func isMissingUnitError(err error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, "not loaded") || strings.Contains(text, "No such file")
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
		return nil, fmt.Errorf("hostagent: stat %s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("hostagent: read %s: %w", path, err)
	}
	return &fileBackup{exists: true, mode: info.Mode(), data: data}, nil
}

func restoreFile(path string, backup *fileBackup) error {
	if backup == nil || !backup.exists {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("hostagent: remove %s: %w", path, err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("hostagent: create parent for %s: %w", path, err)
	}
	if err := os.WriteFile(path, backup.data, backup.mode); err != nil {
		return fmt.Errorf("hostagent: restore %s: %w", path, err)
	}
	return nil
}

func joinErrors(errs []error) error {
	var filtered []error
	for _, err := range errs {
		if err != nil {
			filtered = append(filtered, err)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return fmt.Errorf("%v", filtered)
}
