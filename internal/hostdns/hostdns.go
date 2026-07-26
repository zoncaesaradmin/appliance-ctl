// Package hostdns prepares the appliance host so LAN DNS (CoreDNS on
// hostNetwork :53) can bind, and so the node short hostname stays
// resolvable for sudo/preflight even when uplink or MagicDNS is flaky.
//
// On Ubuntu, systemd-resolved's stub listener owns 127.0.0.53:53 (and
// often 127.0.0.54:53), which blocks any process from binding *:53 —
// including CoreDNS. The installer owns this reconfiguration for
// dns-capable profiles and restores the stub on rollback or uninstall.
//
// Disabling the stub switches /etc/resolv.conf to uplink resolvers. Short
// hostnames that previously resolved only via the stub (for example
// Tailscale MagicDNS) would then fail preflight's internal-dns-resolvable
// check. EnsureNodeHostsEntry therefore seeds a durable managed /etc/hosts
// block for the node name → LAN IPv4; that block is intentionally kept
// across uninstall so the next preflight does not depend on MagicDNS.
package hostdns

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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

	hostsBeginMarker = "# BEGIN zon-appliance-dns"
	hostsEndMarker   = "# END zon-appliance-dns"
)

// HostsPath is the hosts file Prepare manages. Tests may override it.
var HostsPath = "/etc/hosts"

// listenTCP53 and sleep are overridden in tests.
var (
	listenTCP53 = func() (net.Listener, error) { return net.Listen("tcp", ":53") }
	sleep       = time.Sleep
)

const (
	port53ReadyTimeout = 3 * time.Second
	port53ReadyPoll    = 100 * time.Millisecond
)

const dropInContents = `# Managed by zonctl for appliance LAN DNS (hostNetwork CoreDNS on :53).
# Do not edit by hand; uninstall/rollback removes this drop-in.
[Resolve]
DNSStubListener=no
`

// PrepareConfig identifies the node so Prepare can keep its hostname
// resolvable after the stub listener is disabled.
type PrepareConfig struct {
	Hostname string
	IPv4     string
	// Aliases are extra names written on the same hosts line (FQDN, public
	// host, TLS SANs). The short Hostname is always included.
	Aliases []string
}

// PrepareResult describes what Prepare changed so callers can evidence
// and roll back precisely.
type PrepareResult struct {
	Changed            bool
	WroteDropIn        bool
	RelinkedResolvConf bool
	WroteHostsEntry    bool
	PreviousResolvLink string
}

// NeedsStubDisable reports whether a wildcard bind on TCP/53 currently
// fails. When false, Prepare still ensures the drop-in/hosts contract.
func NeedsStubDisable() bool {
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

// waitUntilWildcard53Free polls until a wildcard TCP :53 bind succeeds or
// timeout elapses. systemd-resolved can take a short time after restart to
// drop 127.0.0.53/54 even when DNSStubListener=no is already on disk.
func waitUntilWildcard53Free(timeout, poll time.Duration) bool {
	if timeout <= 0 {
		return !portConflictOnWildcard53()
	}
	if poll <= 0 {
		poll = port53ReadyPoll
	}
	deadline := time.Now().Add(timeout)
	for {
		if !portConflictOnWildcard53() {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		sleep(poll)
	}
}

// Prepare disables the systemd-resolved stub listener when it would block
// CoreDNS from binding *:53, points /etc/resolv.conf at the uplink
// resolv.conf, and seeds a managed /etc/hosts entry so the node hostname
// remains resolvable for preflight and early install steps. It is
// idempotent.
func Prepare(cfg PrepareConfig) (PrepareResult, error) {
	var result PrepareResult
	hostname := strings.TrimSpace(cfg.Hostname)
	ipv4 := strings.TrimSpace(cfg.IPv4)
	if hostname == "" {
		return result, fmt.Errorf("hostdns: hostname is required so the node name stays resolvable after disabling the stub resolver")
	}
	if ip := net.ParseIP(ipv4); ip == nil || ip.To4() == nil {
		return result, fmt.Errorf("hostdns: ipv4 %q is required (node LAN address for /etc/hosts)", cfg.IPv4)
	}

	needStubWork := NeedsStubDisable()
	if !needStubWork {
		if serviceActive("systemd-resolved") {
			if _, err := os.Stat(DropInPath); err != nil {
				needStubWork = true
			}
		}
	}

	if needStubWork {
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

		if !waitUntilWildcard53Free(port53ReadyTimeout, port53ReadyPoll) {
			// Uninstall with KillMode=process can leave appliance-dns CoreDNS
			// reparented to init while still bound to *:53. Reap that known
			// orphan, then wait again for the bind to succeed.
			if _, releaseErr := releaseOrphanCoreDNSListeners(); releaseErr != nil {
				_ = Restore()
				return result, fmt.Errorf("hostdns: release leftover appliance CoreDNS on port 53: %w", releaseErr)
			}
			if !waitUntilWildcard53Free(port53ReadyTimeout, port53ReadyPoll) {
				_ = Restore()
				return result, fmt.Errorf("hostdns: port 53 is still bound after disabling systemd-resolved stub; stop the conflicting DNS service before installing a dns-capable profile")
			}
		}
	}

	wroteHosts, err := EnsureNodeHostsEntry(PrepareConfig{Hostname: hostname, IPv4: ipv4, Aliases: cfg.Aliases})
	if err != nil {
		_ = Restore()
		return result, err
	}
	if wroteHosts {
		result.WroteHostsEntry = true
		result.Changed = true
	}

	if addrs, lookupErr := net.LookupHost(hostname); lookupErr != nil || len(addrs) == 0 {
		_ = Restore()
		if lookupErr != nil {
			return result, fmt.Errorf("hostdns: hostname %q still does not resolve after writing %s: %w", hostname, HostsPath, lookupErr)
		}
		return result, fmt.Errorf("hostdns: hostname %q still does not resolve after writing %s", hostname, HostsPath)
	}
	return result, nil
}

// Restore removes the appliance-owned resolved drop-in and restores the
// stub resolv.conf symlink when resolved is active. The managed /etc/hosts
// node-name block is left in place so uninstall does not reintroduce
// MagicDNS-only hostname resolution for the next preflight.
func Restore() error {
	var errs []error
	if err := os.Remove(DropInPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("hostdns: remove resolved drop-in: %w", err))
	}
	if serviceActive("systemd-resolved") {
		if err := restartResolved(); err != nil {
			errs = append(errs, err)
		}
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

// EnsureNodeHostsEntry writes a durable managed /etc/hosts block mapping
// Hostname (and optional Aliases) to IPv4. It is safe to call from
// preflight and install; identical content is a no-op.
func EnsureNodeHostsEntry(cfg PrepareConfig) (bool, error) {
	hostname := strings.TrimSpace(cfg.Hostname)
	ipv4 := strings.TrimSpace(cfg.IPv4)
	if hostname == "" {
		return false, fmt.Errorf("hostdns: hostname is required for /etc/hosts seeding")
	}
	if ip := net.ParseIP(ipv4); ip == nil || ip.To4() == nil {
		return false, fmt.Errorf("hostdns: ipv4 %q is required for /etc/hosts seeding", cfg.IPv4)
	}
	return ensureHostsEntry(hostname, ipv4, cfg.Aliases)
}

// PreferredLocalIPv4 returns the first candidate that parses as a literal
// IPv4 address, otherwise the first non-loopback interface IPv4.
func PreferredLocalIPv4(candidates ...string) string {
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if ip := net.ParseIP(candidate); ip != nil && ip.To4() != nil {
			return candidate
		}
	}
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range ifaces {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP == nil || ipNet.IP.IsLoopback() {
			continue
		}
		if v4 := ipNet.IP.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
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

func ensureHostsEntry(hostname, ipv4 string, aliases []string) (bool, error) {
	names := uniqueHostNames(hostname, aliases)
	line := ipv4 + " " + strings.Join(names, " ")
	block := hostsBeginMarker + "\n" + line + "\n" + hostsEndMarker + "\n"

	existing, err := os.ReadFile(HostsPath)
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("hostdns: read %s: %w", HostsPath, err)
	}
	body := string(existing)
	if strings.Contains(body, block) {
		return false, nil
	}
	updated, err := replaceOrAppendHostsBlock(body, block)
	if err != nil {
		return false, err
	}
	if updated == body {
		return false, nil
	}
	if err := os.WriteFile(HostsPath, []byte(updated), 0o644); err != nil {
		return false, fmt.Errorf("hostdns: write %s: %w", HostsPath, err)
	}
	return true, nil
}

func removeHostsEntry() error {
	existing, err := os.ReadFile(HostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("hostdns: read %s: %w", HostsPath, err)
	}
	updated, changed := stripHostsBlock(string(existing))
	if !changed {
		return nil
	}
	if err := os.WriteFile(HostsPath, []byte(updated), 0o644); err != nil {
		return fmt.Errorf("hostdns: rewrite %s without appliance block: %w", HostsPath, err)
	}
	return nil
}

func replaceOrAppendHostsBlock(body, block string) (string, error) {
	start := strings.Index(body, hostsBeginMarker)
	if start < 0 {
		if body != "" && !strings.HasSuffix(body, "\n") {
			body += "\n"
		}
		return body + block, nil
	}
	end := strings.Index(body[start:], hostsEndMarker)
	if end < 0 {
		return "", fmt.Errorf("hostdns: %s has a malformed %s block", HostsPath, hostsBeginMarker)
	}
	end = start + end + len(hostsEndMarker)
	for end < len(body) && (body[end] == '\n' || body[end] == '\r') {
		end++
	}
	return body[:start] + block + body[end:], nil
}

func stripHostsBlock(body string) (string, bool) {
	start := strings.Index(body, hostsBeginMarker)
	if start < 0 {
		return body, false
	}
	end := strings.Index(body[start:], hostsEndMarker)
	if end < 0 {
		return body, false
	}
	end = start + end + len(hostsEndMarker)
	for end < len(body) && (body[end] == '\n' || body[end] == '\r') {
		end++
	}
	return body[:start] + body[end:], true
}

func uniqueHostNames(hostname string, aliases []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, 1+len(aliases))
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || net.ParseIP(name) != nil || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	add(hostname)
	for _, alias := range aliases {
		add(alias)
	}
	return out
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
