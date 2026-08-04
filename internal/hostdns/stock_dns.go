package hostdns

import (
	"fmt"
	"os/exec"
	"strings"
)

// Stock host DNS/AP units that dpkg postinst may start. They bind
// wildcard :53 (dnsmasq) or grab wireless (hostapd) and block
// appliance-dns hostNetwork CoreDNS or appliance-managed AP instances.
var stockDNSUnits = []string{
	"dnsmasq.service",
	"hostapd.service",
}

// runSystemctl is replaced in tests.
var runSystemctl = func(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// releaseStockDNSListeners stops and disables stock dnsmasq/hostapd so a
// previous WiFi-AP host-package install (or any other use of the Debian
// units) cannot hold *:53 across a reinstall. Missing units are ignored.
func releaseStockDNSListeners() error {
	var msgs []string
	for _, unit := range stockDNSUnits {
		// stop/disable/mask; ignore "not found" style failures.
		for _, op := range []string{"stop", "disable", "mask"} {
			if err := runSystemctl(op, unit); err != nil && !stockUnitMissing(err) {
				msgs = append(msgs, err.Error())
			}
		}
	}
	// Cover daemon-started-without-unit leftovers (rare but cheap).
	_ = exec.Command("pkill", "-x", "dnsmasq").Run()
	if len(msgs) > 0 {
		return fmt.Errorf("hostdns: release stock DNS services: %s", strings.Join(msgs, "; "))
	}
	return nil
}

func stockUnitMissing(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "not found") ||
		strings.Contains(text, "could not be found") ||
		strings.Contains(text, "not loaded") ||
		strings.Contains(text, "no such file") ||
		strings.Contains(text, "does not exist") ||
		strings.Contains(text, "invalid unit name") ||
		strings.Contains(text, "unit file") && strings.Contains(text, "does not exist")
}
