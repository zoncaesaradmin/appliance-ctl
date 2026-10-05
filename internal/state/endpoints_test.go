package state_test

import (
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

func TestIPv4FromNodeName(t *testing.T) {
	ip, ok := state.IPv4FromNodeName("192-168-1-155")
	if !ok || ip != "192.168.1.155" {
		t.Fatalf("IPv4FromNodeName(dash) = %q %v", ip, ok)
	}
	ip, ok = state.IPv4FromNodeName("192.168.1.153")
	if !ok || ip != "192.168.1.153" {
		t.Fatalf("IPv4FromNodeName(dotted) = %q %v", ip, ok)
	}
	if _, ok := state.IPv4FromNodeName("control-1"); ok {
		t.Fatal("hostname must not parse as IPv4")
	}
}

func TestKnownAPIEndpointsIncludesEveryPrimeIP(t *testing.T) {
	cluster := &state.Cluster{
		ControlEndpoint: "https://192.168.1.155:6443",
		ControlEndpoints: []string{
			"https://192.168.1.153:6443",
		},
		Nodes: []state.ClusterNode{
			{Name: "192-168-1-155", Role: state.NodeRoleControlPlane},
			{Name: "192-168-1-152", Role: state.NodeRoleControlPlane, Roles: []string{state.NodeRoleControlPlane}},
			{Name: "192-168-1-154", Role: state.NodeRoleWorker},
		},
	}
	got := cluster.KnownAPIEndpoints()
	want := map[string]bool{
		"https://192.168.1.155:6443": true,
		"https://192.168.1.153:6443": true,
		"https://192.168.1.152:6443": true,
	}
	if len(got) != 3 {
		t.Fatalf("KnownAPIEndpoints = %#v", got)
	}
	for _, endpoint := range got {
		if !want[endpoint] {
			t.Fatalf("unexpected endpoint %q in %#v", endpoint, got)
		}
	}
	if !cluster.AcceptsAPIEndpoint("https://192.168.1.152:6443") {
		t.Fatal("extra prime API URL must be accepted")
	}
	if cluster.AcceptsAPIEndpoint("https://192.168.1.200:6443") {
		t.Fatal("unknown IP must be rejected")
	}
}

func TestAcceptsAPIEndpointInitialPin(t *testing.T) {
	cluster := &state.Cluster{}
	if !cluster.AcceptsAPIEndpoint("https://192.168.1.155:6443") {
		t.Fatal("empty inventory must accept the first API URL")
	}
	if cluster.AcceptsAPIEndpoint("http://192.168.1.155:6443") {
		t.Fatal("http must be rejected")
	}
}

func TestAddAPIEndpointsDoesNotReplacePreferred(t *testing.T) {
	cluster := &state.Cluster{}
	cluster.SetPreferredAPI("192.168.1.155")
	cluster.AddAPIEndpoints("192.168.1.153", "192.168.1.155", "not-an-ip")
	if cluster.ControlEndpoint != "https://192.168.1.155:6443" {
		t.Fatalf("preferred API = %q", cluster.ControlEndpoint)
	}
	if len(cluster.ControlEndpoints) != 1 || cluster.ControlEndpoints[0] != "https://192.168.1.153:6443" {
		t.Fatalf("ControlEndpoints = %#v", cluster.ControlEndpoints)
	}
	ips := cluster.PrimeIPv4s()
	if len(ips) != 2 || ips[0] != "192.168.1.155" || ips[1] != "192.168.1.153" {
		t.Fatalf("PrimeIPv4s = %#v", ips)
	}
}
