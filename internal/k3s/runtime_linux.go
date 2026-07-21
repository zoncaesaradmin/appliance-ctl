//go:build linux

package k3s

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// k3sContainerdAddress is the well-known containerd socket path used by
// appliance-managed K3s. Leftover shim processes are identified by this
// address in their cmdline so we never touch unrelated containerd hosts.
const k3sContainerdAddress = "/run/k3s/containerd/containerd.sock"

// killLeftoverContainerdShims SIGKILLs containerd-shim processes that
// still point at the K3s containerd socket. Safe to call when K3s is
// already stopped: missing /proc entries and ESRCH are ignored.
func killLeftoverContainerdShims() error {
	pids, err := listK3sContainerdShimPIDs()
	if err != nil {
		return err
	}
	var errs []error
	for _, pid := range pids {
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			errs = append(errs, fmt.Errorf("k3s: kill leftover containerd-shim pid %d: %w", pid, err))
		}
	}
	return errors.Join(errs...)
}

func listK3sContainerdShimPIDs() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("k3s: read /proc for leftover shims: %w", err)
	}
	self := os.Getpid()
	var pids []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 || pid == self {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		if !isK3sContainerdShimCmdline(cmdline) {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

func isK3sContainerdShimCmdline(cmdline []byte) bool {
	// /proc/<pid>/cmdline is NUL-separated; accept either form.
	joined := string(bytes.ReplaceAll(cmdline, []byte{0}, []byte{' '}))
	if !strings.Contains(joined, "containerd-shim") {
		return false
	}
	return strings.Contains(joined, k3sContainerdAddress)
}
