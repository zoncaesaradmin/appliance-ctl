package clustertopology

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validInventory() Inventory {
	return Inventory{
		Topology:      ThreeServerEtcdV1,
		BootstrapNode: "server-a",
		Nodes: []Node{
			{Name: "server-a", Address: "10.0.0.11"},
			{Name: "server-b", Address: "10.0.0.12"},
			{Name: "server-c", Address: "10.0.0.13"},
		},
	}
}

func TestValidateInventory(t *testing.T) {
	if err := validInventory().Validate(); err != nil {
		t.Fatalf("valid inventory rejected: %v", err)
	}
	shared := validInventory()
	shared.Nodes[1].Address = "100.64.1.12"
	if err := shared.Validate(); err != nil {
		t.Fatalf("VPS shared-address peer rejected: %v", err)
	}
	public := validInventory()
	public.Nodes[1].Address = "8.8.8.8"
	if err := public.Validate(); err != nil {
		t.Fatalf("directly assigned VPS address rejected: %v", err)
	}
	tests := []struct {
		name string
		edit func(*Inventory)
	}{
		{"legacy topology", func(in *Inventory) { in.Topology = "single-server" }},
		{"two servers", func(in *Inventory) { in.Nodes = in.Nodes[:2] }},
		{"four servers", func(in *Inventory) { in.Nodes = append(in.Nodes, Node{Name: "server-d", Address: "10.0.0.14"}) }},
		{"duplicate name", func(in *Inventory) { in.Nodes[1].Name = in.Nodes[0].Name }},
		{"duplicate address", func(in *Inventory) { in.Nodes[1].Address = in.Nodes[0].Address }},
		{"loopback peer", func(in *Inventory) { in.Nodes[1].Address = "127.0.0.1" }},
		{"unspecified peer", func(in *Inventory) { in.Nodes[1].Address = "0.0.0.0" }},
		{"bootstrap absent", func(in *Inventory) { in.BootstrapNode = "server-d" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validInventory()
			tt.edit(&in)
			if err := in.Validate(); err == nil {
				t.Fatal("invalid inventory accepted")
			}
		})
	}
}

func TestLoadRejectsUnknownFieldsAndTrailingData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")
	base := `{"topology":"embedded-etcd-v1","bootstrapNode":"server-a","nodes":[{"name":"server-a","address":"10.0.0.11"},{"name":"server-b","address":"10.0.0.12"},{"name":"server-c","address":"10.0.0.13"}]}`
	for _, tt := range []struct {
		name, content string
		wantValid     bool
	}{
		{"valid", base, true},
		{"unknown", strings.Replace(base, `"topology":`, `"unknown":1,"topology":`, 1), false},
		{"trailing", base + ` {}`, false},
		{"oversized", base + strings.Repeat(" ", maxInventoryBytes), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tt.content), 0o640); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if (err == nil) != tt.wantValid {
				t.Fatalf("Load error = %v, wantValid = %v", err, tt.wantValid)
			}
		})
	}
}

func TestDirectAPIEndpointsAndSANs(t *testing.T) {
	in := validInventory()
	if got, want := strings.Join(in.APIEndpoints(), ","), "https://10.0.0.11:6443,https://10.0.0.12:6443,https://10.0.0.13:6443"; got != want {
		t.Fatalf("API endpoints = %q, want %q", got, want)
	}
	if got, want := strings.Join(in.APISANs(), ","), "10.0.0.11,10.0.0.12,10.0.0.13"; got != want {
		t.Fatalf("API SANs = %q, want %q", got, want)
	}
}

func TestValidateLocalAddress(t *testing.T) {
	in := validInventory()
	if err := in.ValidateLocalAddress("server-b", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.0.0.12")}); err != nil {
		t.Fatalf("local server address rejected: %v", err)
	}
	if err := in.ValidateLocalAddress("server-b", []netip.Addr{netip.MustParseAddr("10.0.0.11")}); err == nil {
		t.Fatal("another server's address was accepted as local")
	}
}

func TestInventoryFingerprintIgnoresNodeOrder(t *testing.T) {
	first := validInventory()
	second := validInventory()
	second.Nodes[0], second.Nodes[2] = second.Nodes[2], second.Nodes[0]
	a, err := first.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.Fingerprint()
	if err != nil || a != b {
		t.Fatalf("equivalent inventories differ: %q vs %q, %v", a, b, err)
	}
}
