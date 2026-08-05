package hostpackages

import (
	"errors"
	"testing"
)

func TestQuiesceStockDaemonUnitsIgnoresMissing(t *testing.T) {
	origStop, origDisable, origMask := stopService, disableService, maskService
	t.Cleanup(func() {
		stopService, disableService, maskService = origStop, origDisable, origMask
	})
	var actions []string
	stopService = func(name string) error {
		actions = append(actions, "stop:"+name)
		return errors.New("systemctl is-active dnsmasq.service: exit status 4: Unit dnsmasq.service could not be found")
	}
	disableService = func(name string) error {
		actions = append(actions, "disable:"+name)
		return errors.New("systemctl disable hostapd.service: No such file")
	}
	maskService = func(name string) error {
		actions = append(actions, "mask:"+name)
		return errors.New("systemctl mask dnsmasq.service: not found")
	}
	if err := QuiesceStockDaemonUnits(); err != nil {
		t.Fatalf("expected missing units to be ignored, got: %v", err)
	}
	// avahi-daemon + dnsmasq + hostapd × stop/disable/mask
	if len(actions) != 9 {
		t.Fatalf("actions = %v (len=%d), want stop/disable/mask for three units", actions, len(actions))
	}
	found := map[string]bool{}
	for _, a := range actions {
		found[a] = true
	}
	for _, unit := range []string{"avahi-daemon.service", "dnsmasq.service", "hostapd.service"} {
		for _, op := range []string{"stop", "disable", "mask"} {
			key := op + ":" + unit
			if !found[key] {
				t.Fatalf("missing action %s in %v", key, actions)
			}
		}
	}
}
