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
	if len(actions) != 6 {
		t.Fatalf("actions = %v, want stop/disable/mask for two units", actions)
	}
}
