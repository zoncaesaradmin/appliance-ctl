package k3s_test

import (
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
)

func TestConfig_Render(t *testing.T) {
	cfg := k3s.Config{
		NodeName: "appliance-node",
		DataDir:  "/var/lib/appliance/k3s",
		TLSSANs:  []string{"appliance.internal.example.com", "10.0.0.5"},
	}

	rendered := cfg.Render()

	for _, want := range []string{
		`node-name: "appliance-node"`,
		`data-dir: "/var/lib/appliance/k3s"`,
		`write-kubeconfig-mode: "0640"`,
		"tls-san:",
		`- "appliance.internal.example.com"`,
		`- "10.0.0.5"`,
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("expected rendered config to contain %q, got:\n%s", want, rendered)
		}
	}
}

func TestConfig_Render_OmitsTLSSANWhenEmpty(t *testing.T) {
	cfg := k3s.Config{NodeName: "n", DataDir: "/d"}
	if strings.Contains(cfg.Render(), "tls-san:") {
		t.Error("expected no tls-san section when TLSSANs is empty")
	}
}

func TestUnitConfig_Render(t *testing.T) {
	u := k3s.UnitConfig{BinaryPath: "/opt/appliance/bin/k3s", ConfigPath: "/etc/rancher/k3s/config.yaml"}
	rendered := u.Render()

	for _, want := range []string{
		"ExecStart=/opt/appliance/bin/k3s server --config /etc/rancher/k3s/config.yaml",
		"Restart=always",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("expected rendered unit to contain %q, got:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "ExecStartPre") {
		t.Error("expected no ExecStartPre (no network download step) in a release-owned unit")
	}
}
