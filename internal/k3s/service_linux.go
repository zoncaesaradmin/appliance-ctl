//go:build linux

package k3s

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DetectService reports whether the named systemd unit exists and is
// active. It never mutates anything.
func DetectService(unitName string) (ServiceSignal, error) {
	return ServiceSignal{
		Detected: unitFileExists(unitName),
		Active:   serviceActive(unitName),
	}, nil
}

func unitFileExists(unitName string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "list-unit-files", unitName).Output()
	return err == nil && strings.Contains(string(out), unitName)
}

func serviceActive(unitName string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "is-active", unitName).Output()
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

// EnableAndStart reloads the systemd unit cache, enables the unit for
// boot, and starts it now.
func EnableAndStart(unitName string) error {
	if err := runSystemctl("daemon-reload"); err != nil {
		return err
	}
	if err := runSystemctl("enable", unitName); err != nil {
		return err
	}
	return runSystemctl("start", unitName)
}

// Stop and Restart proxy directly to systemctl.
func Stop(unitName string) error    { return runSystemctl("stop", unitName) }
func Restart(unitName string) error { return runSystemctl("restart", unitName) }

// DaemonReload refreshes systemd's cached unit-file list. `systemctl
// list-unit-files` (what DetectService's unitFileExists uses) reads that
// cache, not the filesystem directly — deleting a unit file without a
// following daemon-reload leaves it reporting the unit as still present
// indefinitely. Any code path that removes a unit file (teardown) must
// call this afterward, the same way EnableAndStart does before starting one.
func DaemonReload() error { return runSystemctl("daemon-reload") }

func runSystemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("k3s: systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Version runs the installed binary's --version flag and returns just
// the K3s version token (e.g. "v1.30.4+k3s1").
func Version(binaryPath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binaryPath, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("k3s: %s --version: %w", binaryPath, err)
	}

	// Expected first line: "k3s version v1.30.4+k3s1 (<git sha>)"
	fields := strings.Fields(string(out))
	if len(fields) < 3 {
		return "", fmt.Errorf("k3s: unexpected --version output: %q", out)
	}
	return fields[2], nil
}
