// Package host detects the read-only signals that preflight checks
// evaluate: OS/architecture, kernel and cgroup state, memory and disk
// capacity, filesystem type, name resolution, port availability, firewall
// presence, and conflicting services. Detection never mutates host state.
package host

import "time"

// Options parameterizes Detect with the appliance-specific values it needs
// to check: where appliance data will live and which ports must be free.
type Options struct {
	DataDir       string
	RequiredPorts []int
}

// Facts is a snapshot of read-only host signals used to evaluate preflight
// checks against the qualified host baseline.
type Facts struct {
	OS            string // e.g. "ubuntu"
	OSVersion     string // e.g. "24.04"
	Arch          string // e.g. "amd64"
	KernelRelease string

	CPUCount      int
	MemTotalBytes uint64

	// CgroupVersion is 1 or 2, or 0 if it could not be determined.
	CgroupVersion int

	UserNamespacesEnabled bool
	IPv4ForwardingEnabled bool

	DataDir           string
	DataDirFilesystem string // e.g. "ext4"
	DataDirFreeBytes  uint64
	DataDirFreeInodes uint64

	TimeSyncActive bool

	Hostname                   string
	HostnameResolvesInternally bool

	RequiredPorts []int
	// PortsInUse maps a required port to a description of what is bound to
	// it, for ports that failed the availability probe.
	PortsInUse map[int]string

	FirewallActive bool
	FirewallName   string
	// FirewallMissingRules lists required ingress rules still missing from
	// a detected firewall policy. Empty means either no firewall is active,
	// or the detected firewall already permits the required baseline ports.
	FirewallMissingRules []string

	// ConflictingServices lists systemd units observed active that are not
	// permitted to coexist with an appliance-owned K3s installation.
	ConflictingServices []string

	DetectedAt time.Time
}
