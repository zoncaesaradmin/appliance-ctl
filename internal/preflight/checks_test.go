package preflight_test

import (
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/host"
	"github.com/zoncaesaradmin/appliance-ctl/internal/preflight"
)

// baseFacts describes a fully-qualified, healthy host: Ubuntu 24.04 amd64
// with every check passing. Each test case starts here and mutates only
// the field(s) relevant to the check under test.
func baseFacts() host.Facts {
	return host.Facts{
		OS:                         "ubuntu",
		OSVersion:                  "24.04",
		Arch:                       "amd64",
		KernelRelease:              "6.8.0-generic",
		CPUCount:                   8,
		MemTotalBytes:              16 * 1024 * 1024 * 1024,
		CgroupVersion:              2,
		UserNamespacesEnabled:      true,
		IPv4ForwardingEnabled:      true,
		DataDir:                    "/var/lib/appliance",
		DataDirFilesystem:          "ext4",
		DataDirFreeBytes:           100 * 1024 * 1024 * 1024,
		DataDirFreeInodes:          1_000_000,
		TimeSyncActive:             true,
		Hostname:                   "appliance.internal.example.com",
		HostnameResolvesInternally: true,
		RequiredPorts:              []int{6443, 10250, 8472},
		PortsInUse:                 map[int]string{},
		FirewallActive:             false,
	}
}

func statusOf(t *testing.T, checks []preflight.Check, id string) preflight.Status {
	t.Helper()
	for _, c := range checks {
		if c.ID == id {
			return c.Status
		}
	}
	t.Fatalf("no check with id %q found", id)
	return ""
}

func TestChecks_HealthyHostAllPass(t *testing.T) {
	checks := preflight.Run(baseFacts())
	for _, c := range checks {
		if c.Status != preflight.StatusPass {
			t.Errorf("check %q: expected pass on healthy host, got %s: %s", c.ID, c.Status, c.Message)
		}
		if c.Message == "" {
			t.Errorf("check %q: expected non-empty message", c.ID)
		}
	}
	if got := preflight.OverallStatus(checks); got != preflight.StatusPass {
		t.Errorf("OverallStatus: expected pass, got %s", got)
	}
}

func TestChecks_MemoryMinimumBoundaryPasses(t *testing.T) {
	facts := baseFacts()
	facts.MemTotalBytes = preflight.MinMemoryBytes

	checks := preflight.Run(facts)
	if got := statusOf(t, checks, "memory-min"); got != preflight.StatusPass {
		t.Errorf("memory-min: expected pass at exact minimum, got %s", got)
	}
}

func TestChecks_SupportedOSVersions(t *testing.T) {
	for _, version := range []string{"22.04", "24.04"} {
		t.Run(version, func(t *testing.T) {
			facts := baseFacts()
			facts.OSVersion = version
			checks := preflight.Run(facts)
			if got := statusOf(t, checks, "os-arch-supported"); got != preflight.StatusPass {
				t.Errorf("expected Ubuntu %s to be supported, got %s", version, got)
			}
		})
	}
}

func TestChecks_UnsupportedHost(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*host.Facts)
	}{
		{"wrong-os", func(f *host.Facts) { f.OS = "rhel" }},
		{"wrong-version", func(f *host.Facts) { f.OSVersion = "20.04" }},
		{"wrong-arch", func(f *host.Facts) { f.Arch = "arm64" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := baseFacts()
			tc.mutate(&facts)
			checks := preflight.Run(facts)
			if got := statusOf(t, checks, "os-arch-supported"); got != preflight.StatusUnsupported {
				t.Errorf("expected unsupported, got %s", got)
			}
			if got := preflight.OverallStatus(checks); got != preflight.StatusUnsupported {
				t.Errorf("OverallStatus: expected unsupported, got %s", got)
			}
		})
	}
}

func TestChecks_NonEXT4Filesystem(t *testing.T) {
	facts := baseFacts()
	facts.DataDirFilesystem = "xfs"
	checks := preflight.Run(facts)
	if got := statusOf(t, checks, "data-dir-filesystem-ext4"); got != preflight.StatusUnsupported {
		t.Errorf("expected unsupported, got %s", got)
	}
}

func TestChecks_OperatorActionCases(t *testing.T) {
	cases := []struct {
		name   string
		id     string
		mutate func(*host.Facts)
	}{
		{"low-cpu", "cpu-count-min", func(f *host.Facts) { f.CPUCount = 2 }},
		{"low-memory", "memory-min", func(f *host.Facts) { f.MemTotalBytes = 1024 * 1024 * 1024 }},
		{"low-disk-space", "data-dir-free-space", func(f *host.Facts) { f.DataDirFreeBytes = 1024 }},
		{"low-inodes", "data-dir-free-inodes", func(f *host.Facts) { f.DataDirFreeInodes = 10 }},
		{"cgroup-v1", "cgroup-v2-enabled", func(f *host.Facts) { f.CgroupVersion = 1 }},
		{"userns-disabled", "kernel-user-namespaces-enabled", func(f *host.Facts) { f.UserNamespacesEnabled = false }},
		{"time-not-synced", "time-sync-active", func(f *host.Facts) { f.TimeSyncActive = false }},
		{"dns-not-resolvable", "internal-dns-resolvable", func(f *host.Facts) { f.HostnameResolvesInternally = false }},
		{"invalid-hostname", "hostname-valid-tls-san", func(f *host.Facts) { f.Hostname = "not_a_valid_host!" }},
		{"port-in-use", "required-ports-available", func(f *host.Facts) { f.PortsInUse = map[int]string{6443: "some-service"} }},
		{"firewall-active", "firewall-detected", func(f *host.Facts) {
			f.FirewallActive = true
			f.FirewallName = "ufw"
			f.FirewallMissingRules = []string{"6443/tcp"}
		}},
		{"conflicting-service", "no-conflicting-services", func(f *host.Facts) { f.ConflictingServices = []string{"docker"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := baseFacts()
			tc.mutate(&facts)
			checks := preflight.Run(facts)
			if got := statusOf(t, checks, tc.id); got != preflight.StatusOperatorAction {
				t.Errorf("check %q: expected operator-action, got %s", tc.id, got)
			}
		})
	}
}

func TestChecks_UFWPassesWhenRequiredRulesExist(t *testing.T) {
	facts := baseFacts()
	facts.FirewallActive = true
	facts.FirewallName = "ufw"
	facts.FirewallMissingRules = nil

	checks := preflight.Run(facts)
	if got := statusOf(t, checks, "firewall-detected"); got != preflight.StatusPass {
		t.Errorf("expected pass for ufw when required rules exist, got %s", got)
	}
}

func TestChecks_UFWRequiresRulesWhenMissing(t *testing.T) {
	facts := baseFacts()
	facts.FirewallActive = true
	facts.FirewallName = "ufw"
	facts.FirewallMissingRules = []string{"6443/tcp", "10250/tcp", "8472/udp"}

	checks := preflight.Run(facts)
	if got := statusOf(t, checks, "firewall-detected"); got != preflight.StatusOperatorAction {
		t.Errorf("expected operator-action for ufw with missing required rules, got %s", got)
	}
}

func TestChecks_AutoFix(t *testing.T) {
	facts := baseFacts()
	facts.IPv4ForwardingEnabled = false
	checks := preflight.Run(facts)
	if got := statusOf(t, checks, "ipv4-forwarding-enabled"); got != preflight.StatusAutoFix {
		t.Errorf("expected auto-fix, got %s", got)
	}
	if got := preflight.OverallStatus(checks); got != preflight.StatusAutoFix {
		t.Errorf("OverallStatus: expected auto-fix (no worse findings present), got %s", got)
	}
}

func TestChecks_NonLinuxSignalsReportUnsupported(t *testing.T) {
	facts := baseFacts()
	facts.KernelRelease = "" // simulates the !linux Detect() fallback
	checks := preflight.Run(facts)

	linuxOnlyChecks := []string{
		"data-dir-filesystem-ext4",
		"data-dir-free-space",
		"data-dir-free-inodes",
		"cgroup-v2-enabled",
		"kernel-user-namespaces-enabled",
		"ipv4-forwarding-enabled",
		"time-sync-active",
		"internal-dns-resolvable",
	}
	for _, id := range linuxOnlyChecks {
		if got := statusOf(t, checks, id); got != preflight.StatusUnsupported {
			t.Errorf("check %q: expected unsupported when KernelRelease is empty, got %s", id, got)
		}
	}
}

func TestChecks_OverallStatusPrioritizesMostSevere(t *testing.T) {
	facts := baseFacts()
	facts.IPv4ForwardingEnabled = false // auto-fix
	facts.CPUCount = 1                  // operator-action
	facts.OS = "rhel"                   // unsupported

	checks := preflight.Run(facts)
	if got := preflight.OverallStatus(checks); got != preflight.StatusUnsupported {
		t.Errorf("expected unsupported to take priority, got %s", got)
	}
}
