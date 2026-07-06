package preflight

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/zoncaesaradmin/appliance-ctl/internal/host"
)

// Status is a preflight finding classification. It intentionally has only
// the four values from the plan's Host Preflight Policy; broader
// evidence.v1 statuses (fail, skipped) belong to other operations, not
// host preflight.
type Status string

const (
	StatusPass           Status = "pass"
	StatusAutoFix        Status = "auto-fix"
	StatusOperatorAction Status = "operator-action"
	StatusUnsupported    Status = "unsupported"
)

// result is the pure evaluation outcome of a single check, before the
// runner attaches identity, timing, and evidence metadata.
type result struct {
	Status      Status
	Message     string
	Remediation string
}

type checkDef struct {
	ID       string
	Category string
	Eval     func(host.Facts) result
}

var checkDefs = []checkDef{
	{"os-arch-supported", "host", checkOSArch},
	{"cpu-count-min", "host", checkCPUCount},
	{"memory-min", "host", checkMemory},
	{"data-dir-filesystem-ext4", "storage", checkFilesystem},
	{"data-dir-free-space", "storage", checkFreeSpace},
	{"data-dir-free-inodes", "storage", checkFreeInodes},
	{"cgroup-v2-enabled", "host", checkCgroupV2},
	{"kernel-user-namespaces-enabled", "host", checkUserNamespaces},
	{"ipv4-forwarding-enabled", "host", checkIPv4Forwarding},
	{"time-sync-active", "host", checkTimeSync},
	{"internal-dns-resolvable", "network", checkDNS},
	{"hostname-valid-tls-san", "network", checkHostnameTLSSAN},
	{"required-ports-available", "network", checkPorts},
	{"firewall-detected", "security", checkFirewall},
	{"no-conflicting-services", "host", checkConflictingServices},
}

// isLinuxHost reports whether Facts were gathered by the real Linux
// detector. On any other platform, Linux-only signals are left at their
// zero value and the corresponding checks report unsupported rather than
// guessing.
func isLinuxHost(f host.Facts) bool {
	return f.KernelRelease != ""
}

func checkOSArch(f host.Facts) result {
	if f.OS == SupportedOS && isSupportedOSVersion(f.OSVersion) && f.Arch == SupportedArch {
		return result{StatusPass, fmt.Sprintf("host is %s %s (%s), matching the qualified baseline", f.OS, f.OSVersion, f.Arch), ""}
	}
	return result{
		StatusUnsupported,
		fmt.Sprintf("host is %s %s (%s); qualified baseline is %s %s (%s)", f.OS, f.OSVersion, f.Arch, SupportedOS, strings.Join(SupportedOSVersions, "/"), SupportedArch),
		fmt.Sprintf("install on %s %s (%s); additional platforms require their own qualification", SupportedOS, strings.Join(SupportedOSVersions, " or "), SupportedArch),
	}
}

func checkCPUCount(f host.Facts) result {
	if f.CPUCount >= MinCPUCount {
		return result{StatusPass, fmt.Sprintf("%d CPUs available, meets the %d CPU minimum", f.CPUCount, MinCPUCount), ""}
	}
	return result{
		StatusOperatorAction,
		fmt.Sprintf("%d CPUs available, below the %d CPU minimum", f.CPUCount, MinCPUCount),
		fmt.Sprintf("provision at least %d CPUs for this host", MinCPUCount),
	}
}

func checkMemory(f host.Facts) result {
	if f.MemTotalBytes >= MinMemoryBytes {
		return result{StatusPass, "memory meets the minimum requirement", ""}
	}
	return result{
		StatusOperatorAction,
		fmt.Sprintf("%d bytes of memory available, below the %d byte minimum", f.MemTotalBytes, MinMemoryBytes),
		fmt.Sprintf("provision at least %d bytes (%d GiB) of memory for this host", MinMemoryBytes, MinMemoryBytes/(1024*1024*1024)),
	}
}

func checkFilesystem(f host.Facts) result {
	if !isLinuxHost(f) {
		return result{StatusUnsupported, "filesystem type cannot be determined outside a Linux host", "install on a qualified Linux host baseline (see os-arch-supported) to evaluate this check"}
	}
	if f.DataDirFilesystem == SupportedFilesystem {
		return result{StatusPass, "appliance data directory is on ext4", ""}
	}
	return result{
		StatusUnsupported,
		fmt.Sprintf("appliance data directory filesystem is %q; v1 requires ext4", f.DataDirFilesystem),
		"format or remount the appliance data directory on a local ext4 filesystem",
	}
}

func checkFreeSpace(f host.Facts) result {
	if !isLinuxHost(f) {
		return result{StatusUnsupported, "free disk space cannot be determined outside a Linux host", "install on a qualified Linux host baseline (see os-arch-supported) to evaluate this check"}
	}
	if f.DataDirFreeBytes >= MinDataDirFreeBytes {
		return result{StatusPass, "appliance data directory has sufficient free space", ""}
	}
	return result{
		StatusOperatorAction,
		fmt.Sprintf("%d bytes free, below the %d byte minimum", f.DataDirFreeBytes, MinDataDirFreeBytes),
		fmt.Sprintf("free or provision at least %d bytes (%d GiB) on the appliance data directory", MinDataDirFreeBytes, MinDataDirFreeBytes/(1024*1024*1024)),
	}
}

func checkFreeInodes(f host.Facts) result {
	if !isLinuxHost(f) {
		return result{StatusUnsupported, "free inode count cannot be determined outside a Linux host", "install on a qualified Linux host baseline (see os-arch-supported) to evaluate this check"}
	}
	if f.DataDirFreeInodes >= MinDataDirFreeInodes {
		return result{StatusPass, "appliance data directory has sufficient free inodes", ""}
	}
	return result{
		StatusOperatorAction,
		fmt.Sprintf("%d inodes free, below the %d inode minimum", f.DataDirFreeInodes, MinDataDirFreeInodes),
		"reformat the appliance data directory with a larger inode allocation, or free unused files",
	}
}

func checkCgroupV2(f host.Facts) result {
	if !isLinuxHost(f) {
		return result{StatusUnsupported, "cgroup version cannot be determined outside a Linux host", "install on a qualified Linux host baseline (see os-arch-supported) to evaluate this check"}
	}
	if f.CgroupVersion == 2 {
		return result{StatusPass, "cgroup v2 (unified hierarchy) is active", ""}
	}
	return result{
		StatusOperatorAction,
		fmt.Sprintf("cgroup version %d detected; cgroup v2 is required", f.CgroupVersion),
		"enable the unified cgroup hierarchy (systemd.unified_cgroup_hierarchy=1) and reboot",
	}
}

func checkUserNamespaces(f host.Facts) result {
	if !isLinuxHost(f) {
		return result{StatusUnsupported, "user namespace support cannot be determined outside a Linux host", "install on a qualified Linux host baseline (see os-arch-supported) to evaluate this check"}
	}
	if f.UserNamespacesEnabled {
		return result{StatusPass, "kernel and user namespaces are enabled", ""}
	}
	return result{
		StatusOperatorAction,
		"kernel user namespaces are disabled",
		"enable user namespaces (e.g. set kernel.unprivileged_userns_clone=1) and reboot",
	}
}

func checkIPv4Forwarding(f host.Facts) result {
	if !isLinuxHost(f) {
		return result{StatusUnsupported, "IPv4 forwarding cannot be determined outside a Linux host", "install on a qualified Linux host baseline (see os-arch-supported) to evaluate this check"}
	}
	if f.IPv4ForwardingEnabled {
		return result{StatusPass, "IPv4 forwarding is enabled", ""}
	}
	return result{
		StatusAutoFix,
		"IPv4 forwarding (net.ipv4.ip_forward) is disabled",
		"installer will set net.ipv4.ip_forward=1; no reboot required",
	}
}

func checkTimeSync(f host.Facts) result {
	if !isLinuxHost(f) {
		return result{StatusUnsupported, "time synchronization cannot be determined outside a Linux host", "install on a qualified Linux host baseline (see os-arch-supported) to evaluate this check"}
	}
	if f.TimeSyncActive {
		return result{StatusPass, "host clock is synchronized", ""}
	}
	return result{
		StatusOperatorAction,
		"host clock is not synchronized to a time source",
		"enable systemd-timesyncd or chrony and confirm NTP synchronization",
	}
}

func checkDNS(f host.Facts) result {
	if !isLinuxHost(f) {
		return result{StatusUnsupported, "internal DNS resolution cannot be determined outside a Linux host", "install on a qualified Linux host baseline (see os-arch-supported) to evaluate this check"}
	}
	if f.HostnameResolvesInternally {
		return result{StatusPass, fmt.Sprintf("hostname %q resolves via internal DNS", f.Hostname), ""}
	}
	return result{
		StatusOperatorAction,
		fmt.Sprintf("hostname %q does not resolve via internal DNS", f.Hostname),
		fmt.Sprintf("create an internal DNS record for %q before continuing", f.Hostname),
	}
}

var validTLSSANHostname = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

func checkHostnameTLSSAN(f host.Facts) result {
	if f.Hostname != "" && len(f.Hostname) <= 253 && validTLSSANHostname.MatchString(f.Hostname) {
		return result{StatusPass, fmt.Sprintf("hostname %q is a valid TLS SAN", f.Hostname), ""}
	}
	return result{
		StatusOperatorAction,
		fmt.Sprintf("hostname %q is not a valid RFC 1123 DNS name usable as a TLS SAN", f.Hostname),
		"set a valid fully-qualified hostname before continuing",
	}
}

func checkPorts(f host.Facts) result {
	if len(f.PortsInUse) == 0 {
		return result{StatusPass, "all required ports are free", ""}
	}
	var occupied []string
	for port, owner := range f.PortsInUse {
		occupied = append(occupied, fmt.Sprintf("%d (%s)", port, owner))
	}
	return result{
		StatusOperatorAction,
		fmt.Sprintf("required ports already in use: %s", strings.Join(occupied, ", ")),
		"stop the conflicting service or reconfigure it to use a different port",
	}
}

func checkFirewall(f host.Facts) result {
	if !f.FirewallActive {
		return result{StatusPass, "no active host firewall detected", ""}
	}
	return result{
		StatusOperatorAction,
		fmt.Sprintf("firewall %q is active", f.FirewallName),
		fmt.Sprintf("confirm required ports are permitted through %s before continuing", f.FirewallName),
	}
}

func checkConflictingServices(f host.Facts) result {
	if len(f.ConflictingServices) == 0 {
		return result{StatusPass, "no conflicting services detected", ""}
	}
	return result{
		StatusOperatorAction,
		fmt.Sprintf("conflicting services active: %s", strings.Join(f.ConflictingServices, ", ")),
		"stop and disable the conflicting services before continuing",
	}
}
