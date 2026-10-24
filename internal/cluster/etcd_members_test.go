package cluster

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

func testEtcdMemberList() map[string]any {
	members := []map[string]any{}
	for i, name := range []string{"server-a", "server-b", "server-c"} {
		address := testThreeServerInventory().Nodes[i].Address
		members = append(members, map[string]any{
			"ID": i + 1, "name": name + "-abc123", "peerURLs": []string{"https://" + address + ":2380"},
			"clientURLs": []string{"https://" + address + ":2379"}, "isLearner": false,
		})
	}
	return map[string]any{"header": map[string]any{"cluster_id": "12345"}, "members": members}
}

func checkEtcdMemberList(t *testing.T, doc map[string]any) InventoryHealth {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return ValidateEtcdMemberList(data, testThreeServerInventory())
}

func TestEtcdMemberListRequiresThreeVotingPlannedPeers(t *testing.T) {
	if health := checkEtcdMemberList(t, testEtcdMemberList()); !health.Healthy {
		t.Fatalf("valid etcd membership rejected: %+v", health)
	}
	tests := []struct {
		name string
		edit func(map[string]any)
	}{
		{"no quorum member", func(doc map[string]any) { doc["members"] = doc["members"].([]map[string]any)[:2] }},
		{"learner", func(doc map[string]any) { doc["members"].([]map[string]any)[1]["isLearner"] = true }},
		{"foreign peer", func(doc map[string]any) {
			doc["members"].([]map[string]any)[1]["peerURLs"] = []string{"https://10.0.0.99:2380"}
		}},
		{"public peer", func(doc map[string]any) {
			doc["members"].([]map[string]any)[1]["peerURLs"] = []string{"https://203.0.113.4:2380"}
		}},
		{"duplicate ID", func(doc map[string]any) { doc["members"].([]map[string]any)[1]["ID"] = 1 }},
		{"duplicate address", func(doc map[string]any) {
			doc["members"].([]map[string]any)[1]["peerURLs"] = []string{"https://10.0.0.11:2380"}
		}},
		{"unstarted", func(doc map[string]any) { doc["members"].([]map[string]any)[1]["name"] = "" }},
		{"HTTP peer", func(doc map[string]any) {
			doc["members"].([]map[string]any)[1]["peerURLs"] = []string{"http://10.0.0.12:2380"}
		}},
		{"missing cluster ID", func(doc map[string]any) { doc["header"] = map[string]any{} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := testEtcdMemberList()
			tt.edit(doc)
			if health := checkEtcdMemberList(t, doc); health.Healthy {
				t.Fatalf("invalid etcd membership accepted: %+v", health)
			}
		})
	}
}

func TestReadLocalEtcdMembershipUsesK3sBundledEtcdctlForMembersAndPeers(t *testing.T) {
	original := etcdctlRun
	t.Cleanup(func() { etcdctlRun = original })
	memberList, err := json.Marshal(testEtcdMemberList())
	if err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	etcdctlRun = func(_ context.Context, dataDir string, args ...string) ([]byte, error) {
		if dataDir != "/var/lib/rancher/k3s" {
			t.Fatalf("dataDir = %q", dataDir)
		}
		calls = append(calls, append([]string(nil), args...))
		if len(calls) == 1 {
			return memberList, nil
		}
		return []byte("https://10.0.0.11:2379 is healthy\nhttps://10.0.0.12:2379 is healthy\nhttps://10.0.0.13:2379 is healthy\n"), nil
	}

	health := ReadLocalEtcdMembership(context.Background(), "/var/lib/rancher/k3s", testThreeServerInventory())
	if !health.Healthy {
		t.Fatalf("membership = %+v", health)
	}
	if len(calls) != 2 {
		t.Fatalf("etcdctl calls = %v", calls)
	}
	if want := []string{"--endpoints=" + localEtcdEndpoint, "member", "list", "--write-out=json"}; !reflect.DeepEqual(calls[0], want) {
		t.Fatalf("member list args = %v, want %v", calls[0], want)
	}
	if got := calls[1]; len(got) != 3 || got[1] != "endpoint" || got[2] != "health" {
		t.Fatalf("peer health args = %v", got)
	}
}

func TestReadLocalEtcdMembershipRejectsMissingPeerHealth(t *testing.T) {
	original := etcdctlRun
	t.Cleanup(func() { etcdctlRun = original })
	memberList, err := json.Marshal(testEtcdMemberList())
	if err != nil {
		t.Fatal(err)
	}
	etcdctlRun = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) > 1 && args[1] == "member" {
			return memberList, nil
		}
		return []byte("https://10.0.0.11:2379 is healthy\n"), nil
	}
	if health := ReadLocalEtcdMembership(context.Background(), "/var/lib/rancher/k3s", testThreeServerInventory()); health.Healthy {
		t.Fatalf("missing peer health was accepted: %+v", health)
	}
}
