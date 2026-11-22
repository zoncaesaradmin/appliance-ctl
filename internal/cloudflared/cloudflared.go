// Package cloudflared installs the optional host-native Cloudflare Tunnel
// connector used by local LAN appliances. The connector is deliberately
// enabled only when the operator supplies a protected tunnel token.
package cloudflared

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/hostagent"
	"github.com/zoncaesaradmin/appliance-ctl/internal/lifecycle"
)

const (
	serviceUser  = "cloudflared"
	unitTemplate = `[Unit]
Description=Zon appliance Cloudflare Tunnel connector (release-owned; do not edit)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s tunnel --no-autoupdate run --token-file %s
Restart=always
RestartSec=5s
User=cloudflared
Group=cloudflared
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=%s

[Install]
WantedBy=multi-user.target
`
)

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)

type InstallSpec struct {
	SourceBinaryPath string
	BinaryDestPath   string
	UnitPath         string
	UnitName         string
	TokenSourcePath  string
	TokenDestPath    string
}

func RenderUnit(binaryPath, tokenPath string) string {
	return fmt.Sprintf(unitTemplate, binaryPath, tokenPath, tokenPath)
}

// InstallOrUpdate installs the verified connector and protected token, then
// enables and restarts its systemd unit. The returned function restores the
// prior files and service state when a later install step fails.
func InstallOrUpdate(spec InstallSpec) (func() error, error) {
	if strings.TrimSpace(spec.SourceBinaryPath) == "" || strings.TrimSpace(spec.BinaryDestPath) == "" || strings.TrimSpace(spec.UnitPath) == "" || strings.TrimSpace(spec.UnitName) == "" || strings.TrimSpace(spec.TokenSourcePath) == "" || strings.TrimSpace(spec.TokenDestPath) == "" {
		return nil, fmt.Errorf("cloudflared: sourceBinaryPath, binaryDestPath, unitPath, unitName, tokenSourcePath, and tokenDestPath are required")
	}
	token, err := readProtectedToken(spec.TokenSourcePath)
	if err != nil {
		return nil, err
	}
	if err := ensureServiceAccount(); err != nil {
		return nil, err
	}
	binaryPrev, err := backupFile(spec.BinaryDestPath)
	if err != nil {
		return nil, err
	}
	unitPrev, err := backupFile(spec.UnitPath)
	if err != nil {
		return nil, err
	}
	tokenPrev, err := backupFile(spec.TokenDestPath)
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
		if err := restoreFile(spec.TokenDestPath, tokenPrev); err != nil {
			errs = append(errs, err)
		}
		if err := runSystemctl("daemon-reload"); err != nil {
			errs = append(errs, err)
		}
		if unitPrev.exists {
			if err := runSystemctl("enable", spec.UnitName); err != nil {
				errs = append(errs, err)
			}
			if err := runSystemctl("restart", spec.UnitName); err != nil {
				errs = append(errs, err)
			}
		} else if err := disableAndStop(spec.UnitName); err != nil {
			errs = append(errs, err)
		}
		return joinErrors(errs)
	}

	if err := hostagent.InstallBinary(spec.SourceBinaryPath, spec.BinaryDestPath); err != nil {
		return nil, err
	}
	if err := lifecycle.WriteFileAtomic(spec.UnitPath, []byte(RenderUnit(spec.BinaryDestPath, spec.TokenDestPath)), 0o644); err != nil {
		_ = rollback()
		return nil, fmt.Errorf("cloudflared: write unit: %w", err)
	}
	if err := lifecycle.WriteFileAtomic(spec.TokenDestPath, []byte(token+"\n"), 0o640); err != nil {
		_ = rollback()
		return nil, fmt.Errorf("cloudflared: write token: %w", err)
	}
	if err := os.Chown(spec.TokenDestPath, 0, serviceGroupID()); err != nil {
		_ = rollback()
		return nil, fmt.Errorf("cloudflared: protect token ownership: %w", err)
	}
	if err := runSystemctl("daemon-reload"); err != nil {
		_ = rollback()
		return nil, err
	}
	if err := runSystemctl("enable", spec.UnitName); err != nil {
		_ = rollback()
		return nil, err
	}
	if err := runSystemctl("restart", spec.UnitName); err != nil {
		_ = rollback()
		return nil, err
	}
	return rollback, nil
}

// Uninstall removes the release-owned connector service, binary, and token.
// It is used by uninstall/factory-reset; the Cloudflare account and tunnel
// itself remain operator-owned and are not changed.
func Uninstall(spec InstallSpec) error {
	var errs []error
	if err := disableAndStop(spec.UnitName); err != nil {
		errs = append(errs, err)
	}
	for _, path := range []string{spec.UnitPath, spec.BinaryDestPath, spec.TokenDestPath} {
		if path == "" {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("cloudflared: remove %s: %w", path, err))
		}
	}
	if err := runSystemctl("daemon-reload"); err != nil {
		errs = append(errs, err)
	}
	return joinErrors(errs)
}

func readProtectedToken(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("cloudflared: stat token file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("cloudflared: token file is not regular")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("cloudflared: token file %s must not be group/world accessible", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cloudflared: read token file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 32 || len(token) > 4096 || !tokenPattern.MatchString(token) {
		return "", fmt.Errorf("cloudflared: token file contains an invalid tunnel token")
	}
	return token, nil
}

func ensureServiceAccount() error {
	if _, err := user.Lookup(serviceUser); err == nil {
		return nil
	}
	if err := exec.Command("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", serviceUser).Run(); err != nil {
		if _, lookupErr := user.Lookup(serviceUser); lookupErr == nil {
			return nil
		}
		return fmt.Errorf("cloudflared: create service account: %w", err)
	}
	return nil
}

func serviceGroupID() int {
	g, err := user.LookupGroup(serviceUser)
	if err == nil {
		var gid int
		_, _ = fmt.Sscanf(g.Gid, "%d", &gid)
		return gid
	}
	u, lookupErr := user.Lookup(serviceUser)
	if lookupErr != nil {
		return 0
	}
	var gid int
	_, _ = fmt.Sscanf(u.Gid, "%d", &gid)
	return gid
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
		return nil, fmt.Errorf("cloudflared: stat %s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cloudflared: read %s: %w", path, err)
	}
	return &fileBackup{exists: true, mode: info.Mode(), data: data}, nil
}

func restoreFile(path string, backup *fileBackup) error {
	if backup == nil || !backup.exists {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, backup.data, backup.mode)
}

func disableAndStop(unit string) error {
	var errs []error
	if err := runSystemctl("disable", unit); err != nil && !missingUnit(err) {
		errs = append(errs, err)
	}
	if err := runSystemctl("stop", unit); err != nil && !missingUnit(err) {
		errs = append(errs, err)
	}
	return joinErrors(errs)
}

func runSystemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cloudflared: systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func missingUnit(err error) bool {
	text := err.Error()
	return strings.Contains(text, "not loaded") || strings.Contains(text, "No such file") || strings.Contains(text, "does not exist")
}
func joinErrors(errs []error) error {
	var nonnil []error
	for _, err := range errs {
		if err != nil {
			nonnil = append(nonnil, err)
		}
	}
	if len(nonnil) == 0 {
		return nil
	}
	return fmt.Errorf("%v", nonnil)
}
