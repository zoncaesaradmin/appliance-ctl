package cloudflared

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderUnitUsesPinnedTokenFile(t *testing.T) {
	unit := RenderUnit("/usr/local/lib/zon/bin/cloudflared", "/etc/zon/cloudflared/tunnel-token")
	for _, want := range []string{
		"ExecStart=/usr/local/lib/zon/bin/cloudflared tunnel --no-autoupdate run --token-file /etc/zon/cloudflared/tunnel-token",
		"User=cloudflared",
		"ProtectSystem=strict",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit missing %q:\n%s", want, unit)
		}
	}
}

func TestReadProtectedTokenRejectsWeakPermissionsAndInvalidValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 32)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedToken(path); err == nil {
		t.Fatal("expected group/world-readable token to be rejected")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a tunnel token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedToken(path); err == nil {
		t.Fatal("expected invalid token to be rejected")
	}
}
