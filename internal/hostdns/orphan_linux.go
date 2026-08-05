//go:build linux

package hostdns

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdirs"
)

// releaseOrphanCoreDNSListeners SIGKILLs leftover appliance-dns CoreDNS
// processes that still hold *:53 after K3s uninstall. KillMode=process can
// leave the container PID reparented to init with uid DNSDirOwnerUID.
// Live pods match the same fingerprint; callers only invoke this when :
// 53 must be free for a fresh CoreDNS bind (not when product DNS is OK).
func releaseOrphanCoreDNSListeners() (bool, error) {
	pids, err := listOrphanApplianceCoreDNSPIDS()
	if err != nil {
		return false, err
	}
	if len(pids) == 0 {
		return false, nil
	}
	var errs []error
	for _, pid := range pids {
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			errs = append(errs, fmt.Errorf("hostdns: kill orphan coredns pid %d: %w", pid, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return true, err
	}
	return true, nil
}

// applianceCoreDNSListening reports product CoreDNS (DNSDirOwnerUID + conf)
// still present — typical on upgrade/reconcile when LAN DNS is already up.
func applianceCoreDNSListening() bool {
	pids, err := listOrphanApplianceCoreDNSPIDS()
	return err == nil && len(pids) > 0
}

func listOrphanApplianceCoreDNSPIDS() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("hostdns: read /proc for orphan coredns: %w", err)
	}
	self := os.Getpid()
	wantUID := hostdirs.DNSDirOwnerUID
	var pids []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 || pid == self {
			continue
		}
		status, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if err != nil {
			continue
		}
		if processUID(status) != wantUID {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		if !isApplianceCoreDNSCmdline(cmdline) {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

func processUID(status []byte) int {
	for _, line := range bytes.Split(status, []byte{'\n'}) {
		if !bytes.HasPrefix(line, []byte("Uid:")) {
			continue
		}
		fields := strings.Fields(string(line))
		if len(fields) < 2 {
			return -1
		}
		uid, err := strconv.Atoi(fields[1])
		if err != nil {
			return -1
		}
		return uid
	}
	return -1
}

func isApplianceCoreDNSCmdline(cmdline []byte) bool {
	joined := string(bytes.ReplaceAll(cmdline, []byte{0}, []byte{' '}))
	if !strings.Contains(joined, "coredns") {
		return false
	}
	return strings.Contains(joined, "-conf") || strings.Contains(joined, "/etc/coredns")
}
