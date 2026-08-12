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
	// stop + disable avahi so leftover day-2 enable is not running after install reset.
	cmd := exec.CommandContext(ctx, "systemctl", "stop", mdnsSystemdUnit)
	_ = cmd.Run()
	cmd = exec.CommandContext(ctx, "systemctl", "disable", mdnsSystemdUnit)
	_ = cmd.Run()
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
	Desired bool `json:"desired"`
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
