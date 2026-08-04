package hostdns

import (
	"errors"
	"testing"
)

func TestReleaseStockDNSListenersIgnoresMissingUnits(t *testing.T) {
	orig := runSystemctl
	t.Cleanup(func() { runSystemctl = orig })
	var ops []string
	runSystemctl = func(args ...string) error {
		ops = append(ops, stringsJoin(args))
		return errors.New("systemctl stop dnsmasq.service: Unit dnsmasq.service could not be found")
	}
	if err := releaseStockDNSListeners(); err != nil {
		t.Fatalf("expected missing units ignored, got %v", err)
	}
	if len(ops) != 6 { // stop/disable/mask × 2 units
		t.Fatalf("ops=%v want 6", ops)
	}
}

func stringsJoin(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}
