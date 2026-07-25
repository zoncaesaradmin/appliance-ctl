package hostdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureHostsEntry_IdempotentAndReplaceable(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts")
	if err := os.WriteFile(hosts, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := HostsPath
	HostsPath = hosts
	t.Cleanup(func() { HostsPath = prev })

	wrote, err := ensureHostsEntry("zonsyssrv1", "192.168.1.101", []string{"zonsyssrv1.example.com", "192.0.2.1", "zonsyssrv1"})
	if err != nil {
		t.Fatal(err)
	}
	if !wrote {
		t.Fatal("expected first write to change hosts")
	}
	data, err := os.ReadFile(hosts)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, hostsBeginMarker) || !strings.Contains(text, "192.168.1.101 zonsyssrv1 zonsyssrv1.example.com") {
		t.Fatalf("unexpected hosts content:\n%s", text)
	}

	wrote, err = ensureHostsEntry("zonsyssrv1", "192.168.1.101", []string{"zonsyssrv1.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if wrote {
		t.Fatal("identical block should be idempotent")
	}

	wrote, err = ensureHostsEntry("zonsyssrv1", "192.168.1.200", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !wrote {
		t.Fatal("expected IP change to rewrite hosts block")
	}
	data, err = os.ReadFile(hosts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "192.168.1.200 zonsyssrv1") || strings.Contains(string(data), "192.168.1.101 zonsyssrv1") {
		t.Fatalf("hosts block not replaced:\n%s", data)
	}
	if strings.Count(string(data), hostsBeginMarker) != 1 {
		t.Fatalf("expected a single managed block:\n%s", data)
	}
}

func TestEnsureNodeHostsEntry_Exported(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts")
	if err := os.WriteFile(hosts, []byte("127.0.0.1 localhost\n127.0.1.1 zonsys_srv_1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := HostsPath
	HostsPath = hosts
	t.Cleanup(func() { HostsPath = prev })

	wrote, err := EnsureNodeHostsEntry(PrepareConfig{Hostname: "zonsyssrv1", IPv4: "192.168.1.101"})
	if err != nil {
		t.Fatal(err)
	}
	if !wrote {
		t.Fatal("expected hosts write")
	}
	data, err := os.ReadFile(hosts)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "192.168.1.101 zonsyssrv1") || !strings.Contains(text, "127.0.1.1 zonsys_srv_1") {
		t.Fatalf("expected managed mapping alongside existing cloud-init line:\n%s", text)
	}
}

func TestPreferredLocalIPv4_LiteralWins(t *testing.T) {
	if got := PreferredLocalIPv4("hostname.example", "192.0.2.10", "10.0.0.1"); got != "192.0.2.10" {
		t.Fatalf("PreferredLocalIPv4 = %q, want 192.0.2.10", got)
	}
}

func TestRemoveHostsEntry_StillAvailableForOps(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts")
	content := "127.0.0.1 localhost\n" + hostsBeginMarker + "\n192.168.1.101 zonsyssrv1\n" + hostsEndMarker + "\n# keep\n"
	if err := os.WriteFile(hosts, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := HostsPath
	HostsPath = hosts
	t.Cleanup(func() { HostsPath = prev })
	if err := removeHostsEntry(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(hosts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), hostsBeginMarker) {
		t.Fatalf("expected strip:\n%s", data)
	}
}
