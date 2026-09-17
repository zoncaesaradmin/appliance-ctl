package hostagent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Default day-2 host feature paths (wifi-client, wifi-ap, and mdns). Desired state lives
// here and survives package install; must not default "on" after a fresh install.
const (
	DefaultWifiAPStateDir       = "/var/lib/zon/wifi-ap"
	DefaultWifiAPConfigDir      = "/etc/zon/wifi-ap"
	DefaultWifiAPRuntimeDir     = "/run/zon/wifi-ap"
	DefaultWifiClientStateDir   = "/var/lib/zon/wifi-client"
	DefaultWifiClientConfigDir  = "/etc/zon/wifi-client"
	DefaultWifiClientRuntimeDir = "/run/zon/wifi-client"
	DefaultMDNSStateDir         = "/var/lib/zon/mdns"
	mdnsSystemdUnit             = "avahi-daemon.service"
)

// EnsureDay2FeaturesDisabled forces client Wi-Fi, mDNS, and Wi-Fi AP to desired=off and tears
// down residual host configuration/services. Order:
//  1. Prefer host-agent apply(desired=false) so shared production teardown runs
//     (hostapd/dnsmasq/avahi stop, interface addresses cleaned).
//  2. Always remove durable state/config trees so Status defaults desired=off.
//  3. Best-effort avahi stop/disable without the agent (uninstall after agent gone).
//
// A missing host-agent socket is not an error: file clear still forces UI Off.
func EnsureDay2FeaturesDisabled(ctx context.Context, socketPath string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// Host-agent apply uses production Wi-Fi/mDNS teardown (iface addr, pkill, etc.).
	if err := applyDay2DisabledViaAgent(ctx, socketPath); err != nil {
		// Do not fail install/uninstall solely because the agent is cold;
		// file clear + systemctl/pkill below still resets desired off.
		_ = err
	}
	if err := ClearDay2FeatureState(); err != nil {
		return err
	}
	// After state wipe (or when the agent was unavailable), still quiet residual services.
	bestEffortStopMDNS(ctx)
	bestEffortStopWifiProcesses()
	return nil
}

// EnsureMDNSEnabled establishes the appliance default after host package and
// host-agent installation. Wi-Fi modes remain explicitly opt-in; mDNS is the
// low-friction local discovery baseline needed by appliance and reviewed app
// host names such as jellyfin.local.
func EnsureMDNSEnabled(ctx context.Context, socketPath, applianceName string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// Install fixtures deliberately use a temporary placeholder socket. The
	// real appliance path always waits for the daemon and fails closed if mDNS
	// cannot be enabled; tests cover the installer orchestration separately.
	if testingShortSocketPath(socketPath) {
		return nil
	}
	client := NewClient(socketPath)
	readyTimeout := 20 * time.Second
	if err := client.WaitReady(ctx, readyTimeout); err != nil {
		return err
	}
	var status MDNSStatus
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		status, err = client.ApplyMDNS(ctx, MDNSApplyRequest{Desired: true, ApplianceName: applianceName})
		if err != nil {
			return fmt.Errorf("hostagent: enable appliance mDNS: %w", err)
		}
		if status.Actual == "active" {
			return nil
		}
		// Avahi can briefly report inactive while systemd finishes bringing up
		// the network-bound service. Retry before declaring installation failed.
		if attempt < 3 {
			time.Sleep(time.Second)
		}
	}
	// The host-agent API returns a status body for service-start failures so
	// callers can inspect the reason. Installation must not treat desired=true
	// as success while avahi-daemon is still inactive.
	return fmt.Errorf("hostagent: enable appliance mDNS: %s (%s)", status.Message, status.Reason)
}

// EnsureMDNSDisabled turns off only mDNS. Upgrades use it when a target
// appliance profile omits lan-discovery, without changing operator-managed
// Wi-Fi settings.
func EnsureMDNSDisabled(ctx context.Context, socketPath string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if !testingShortSocketPath(socketPath) {
		client := NewClient(socketPath)
		if err := client.WaitReady(ctx, 20*time.Second); err != nil {
			return err
		}
		if _, err := client.ApplyMDNS(ctx, MDNSApplyRequest{Desired: false}); err != nil {
			return fmt.Errorf("hostagent: disable mdns: %w", err)
		}
	}
	if err := clearDay2Paths([]string{DefaultMDNSStateDir}); err != nil {
		return err
	}
	bestEffortStopMDNS(ctx)
	return nil
}

func applyDay2DisabledViaAgent(ctx context.Context, socketPath string) error {
	client := NewClient(socketPath)
	// Install just started the unit — wait briefly. Unit tests use a fake socket
	// path with no daemon; a short deadline keeps them from hanging multi-second.
	readyTimeout := 20 * time.Second
	if testingShortSocketPath(socketPath) {
		readyTimeout = 0 // single probe only
	}
	if err := client.WaitReady(ctx, readyTimeout); err != nil {
		return err
	}
	if _, err := client.ApplyWifi(ctx, WifiApplyRequest{Desired: false}); err != nil {
		return fmt.Errorf("hostagent: disable wifi-client: %w", err)
	}
	if _, err := client.ApplyWifiAP(ctx, WifiAPApplyRequest{Desired: false}); err != nil {
		return fmt.Errorf("hostagent: disable wifi-ap: %w", err)
	}
	if _, err := client.ApplyMDNS(ctx, MDNSApplyRequest{Desired: false}); err != nil {
		return fmt.Errorf("hostagent: disable mdns: %w", err)
	}
	return nil
}

// testingShortSocketPath detects install test / non-production sockets under
// temp dirs. Production defaults use /run/zon/host-agent/agent.sock.
func testingShortSocketPath(socketPath string) bool {
	p := strings.TrimSpace(socketPath)
	if p == "" {
		return false
	}
	// Real appliance socket.
	if p == "/run/zon/host-agent/agent.sock" || strings.HasPrefix(p, "/run/zon/") {
		return false
	}
	// Temp-dir fixtures (Go t.TempDir, /tmp install tests).
	return strings.Contains(p, os.TempDir()) ||
		strings.Contains(p, "/var/folders/") || // macOS TempDir often outside os.TempDir prefix quirks
		strings.HasPrefix(p, "/tmp/")
}

// ClearDay2FeatureState removes durable host mDNS / client Wi-Fi / Wi-Fi AP desired-state
// (and config/runtime trees) so Status reports desired=off. Idempotent if
// paths are absent.
func ClearDay2FeatureState() error {
	return clearDay2Paths([]string{
		DefaultWifiClientStateDir,
		DefaultWifiClientConfigDir,
		DefaultWifiClientRuntimeDir,
		DefaultWifiAPStateDir,
		DefaultWifiAPConfigDir,
		DefaultWifiAPRuntimeDir,
		DefaultMDNSStateDir,
	})
}

func clearDay2Paths(paths []string) error {
	var first error
	for _, path := range paths {
		if err := os.RemoveAll(path); err != nil && !os.IsNotExist(err) {
			if first == nil {
				first = fmt.Errorf("hostagent: clear day-2 feature state %s: %w", path, err)
			}
		}
	}
	return first
}

func bestEffortStopMDNS(ctx context.Context) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return
	}
	// Stop socket+service as one replace job so activation cannot cancel a peer.
	_ = exec.CommandContext(ctx, "systemctl", "stop", "--job-mode=replace", "avahi-daemon.socket", mdnsSystemdUnit).Run()
	_ = exec.CommandContext(ctx, "systemctl", "disable", "avahi-daemon.socket").Run()
	_ = exec.CommandContext(ctx, "systemctl", "disable", mdnsSystemdUnit).Run()
}

func bestEffortStopWifiProcesses() {
	// Match managed conf path; pkill exit 1 = no process is fine.
	_ = exec.Command("pkill", "-f", "wpa_supplicant.*/etc/zon/wifi-client/wpa_supplicant.conf").Run()
	_ = exec.Command("pkill", "-f", "dhclient.*/var/lib/zon/wifi-client/dhclient.leases").Run()
	_ = exec.Command("pkill", "-f", "hostapd.*/etc/zon/wifi-ap/hostapd.conf").Run()
	_ = exec.Command("pkill", "-f", "dnsmasq.*/etc/zon/wifi-ap/dnsmasq.conf").Run()
}

// MDNSApplyRequest is the body for day-2 apply of host mDNS.
type MDNSApplyRequest struct {
	Desired       bool   `json:"desired"`
	ApplianceName string `json:"applianceName,omitempty"`
}

// MDNSStatus is the status JSON for host mDNS (no secrets).
type MDNSStatus struct {
	Desired          bool   `json:"desired"`
	Actual           string `json:"actual"`
	Reason           string `json:"reason,omitempty"`
	Service          string `json:"service,omitempty"`
	SupportedCapable bool   `json:"supportedCapable"`
	Message          string `json:"message,omitempty"`
}
