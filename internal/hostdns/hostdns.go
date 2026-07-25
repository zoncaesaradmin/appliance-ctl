// Package hostdns prepares the appliance host so LAN DNS (CoreDNS on
// hostNetwork :53) can bind. On Ubuntu, systemd-resolved's stub listener
// owns 127.0.0.53:53 (and often 127.0.0.54:53), which blocks any process
// from binding *:53 — including CoreDNS. The installer owns this
// reconfiguration for dns-capable profiles and restores it on rollback
// or uninstall.
package hostdns

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// DropInPath is the systemd-resolved drop-in the appliance owns.
	DropInPath = "/etc/systemd/resolved.conf.d/99-zon-appliance-dns.conf"
	// UpstreamResolvPath is systemd-resolved's non-stub resolv.conf that
	// lists the real uplink nameservers. After disabling the stub listener
	// we point /etc/resolv.conf here so the host keeps DNS while CoreDNS
	// is not yet listening.
	UpstreamResolvPath = "/run/systemd/resolve/resolv.conf"
	ResolvConfPath     = "/etc/resolv.conf"
)

const dropInContents = `# Managed by zonctl for appliance LAN DNS (hostNetwork CoreDNS on :53).
# Do not edit by hand; uninstall/rollback removes this drop-in.
[Resolve]
DNSStubListener=no
`

// PrepareResult describes what Prepare changed so callers can evidence
// and roll back precisely.
type PrepareResult struct {
	Changed            bool
	WroteDropIn        bool
	RelinkedResolvConf bool
	PreviousResolvLink string
}

// NeedsStubDisable reports whether systemd-resolved's stub listener is
// currently preventing a wildcard bind on TCP/53. When false, Prepare is
// a no-op.
func NeedsStubDisable() bool {
	if _, err := os.Stat("/usr/lib/systemd/systemd-resolved"); err != nil {
		if _, err := os.Stat("/lib/systemd/systemd-resolved"); err != nil {
			// No systemd-resolved binary — nothing for us to reconfigure.
			return portConflictOnWildcard53()
		}
	}
	if !serviceActive("systemd-resolved") {
		return portConflictOnWildcard53()
	}
	return portConflictOnWildcard53()
}

func portConflictOnWildcard53() bool {
	ln, err := listenTCP53()
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}

// Prepare disables the systemd-resolved stub listener when it would block
// CoreDNS from binding *:53, and points /etc/resolv.conf at the uplink
// resolv.conf so the host keeps working DNS during install. It is
// idempotent: a second call with the drop-in already present is a no-op.
func Prepare() (PrepareResult, error) {
	var result PrepareResult
	if !NeedsStubDisable() {
		// Already free (or previously prepared). Still ensure our drop-in
		// exists if resolved is active so a reboot keeps the contract.
		if serviceActive("systemd-resolved") {
			if _, err := os.Stat(DropInPath); err == nil {
				return result, nil
			}
		} else {
			return result, nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(DropInPath), 0o755); err != nil {
		return result, fmt.Errorf("hostdns: create resolved drop-in dir: %w", err)
	}
	if err := os.WriteFile(DropInPath, []byte(dropInContents), 0o644); err != nil {
		return result, fmt.Errorf("hostdns: write resolved drop-in: %w", err)
	}
	result.WroteDropIn = true
	result.Changed = true

	if err := restartResolved(); err != nil {
		_ = os.Remove(DropInPath)
		return result, err
	}

	if err := ensureUpstreamResolvConf(&result); err != nil {
		_ = Restore()
		return result, err
	}

	if portConflictOnWildcard53() {
		_ = Restore()
		return result, fmt.Errorf("hostdns: port 53 is still bound after disabling systemd-resolved stub; stop the conflicting DNS service before installing a dns-capable profile")
	}
	return result, nil
}

// Restore removes the appliance-owned resolved drop-in and restores the
// previous /etc/resolv.conf stub symlink when Prepare changed it.
func Restore() error {
	var errs []error
	if err := os.Remove(DropInPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("hostdns: remove resolved drop-in: %w", err))
	}
	if serviceActive("systemd-resolved") {
		if err := restartResolved(); err != nil {
			errs = append(errs, err)
		}
	}
	// Prefer the stub resolv.conf when resolved is active again so Ubuntu
	// returns to its default DNS mode after uninstall/rollback.
	if serviceActive("systemd-resolved") {
		stub := "/run/systemd/resolve/stub-resolv.conf"
		if _, err := os.Stat(stub); err == nil {
			_ = os.Remove(ResolvConfPath)
			if err := os.Symlink(stub, ResolvConfPath); err != nil {
				errs = append(errs, fmt.Errorf("hostdns: restore stub resolv.conf symlink: %w", err))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%v", errs)
	}
	return nil
}

func ensureUpstreamResolvConf(result *PrepareResult) error {
	if _, err := os.Stat(UpstreamResolvPath); err != nil {
		// Without the uplink file the host may lose DNS; fail closed so
		// operators see a clear prep error instead of a later opaque failure.
		return fmt.Errorf("hostdns: uplink resolv.conf %s missing after disabling stub listener: %w", UpstreamResolvPath, err)
	}
	info, err := os.Lstat(ResolvConfPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("hostdns: stat resolv.conf: %w", err)
	}
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		target, readErr := os.Readlink(ResolvConfPath)
		if readErr == nil {
			result.PreviousResolvLink = target
			if target == UpstreamResolvPath || strings.HasSuffix(target, "/run/systemd/resolve/resolv.conf") {
				return nil
			}
		}
	}
	_ = os.Remove(ResolvConfPath)
	if err := os.Symlink(UpstreamResolvPath, ResolvConfPath); err != nil {
		return fmt.Errorf("hostdns: point resolv.conf at uplink resolvers: %w", err)
	}
	result.RelinkedResolvConf = true
	result.Changed = true
	return nil
}

func restartResolved() error {
	cmd := exec.Command("systemctl", "restart", "systemd-resolved")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("hostdns: restart systemd-resolved: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func serviceActive(name string) bool {
	cmd := exec.Command("systemctl", "is-active", "--quiet", name)
	return cmd.Run() == nil
}

func listenTCP53() (net.Listener, error) {
	return net.Listen("tcp", ":53")
}
