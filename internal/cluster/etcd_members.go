package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zoncaesaradmin/appliance-ctl/internal/clustertopology"
)

const (
	localEtcdEndpoint = "https://127.0.0.1:2379"
	etcdctlPathSuffix = "data/current/bin/etcdctl"
)

// etcdctlRun is injectable so membership checking has no dependency on a live
// embedded-etcd process in unit tests. K3s ships this binary alongside its
// managed etcd and keeps it version-aligned with the server.
var etcdctlRun = func(ctx context.Context, k3sDataDir string, args ...string) ([]byte, error) {
	certDir := filepath.Join(k3sDataDir, "server", "tls", "etcd")
	cmd := exec.CommandContext(ctx, filepath.Join(k3sDataDir, etcdctlPathSuffix), args...)
	cmd.Env = append(os.Environ(),
		"ETCDCTL_API=3",
		"ETCDCTL_CACERT="+filepath.Join(certDir, "server-ca.crt"),
		"ETCDCTL_CERT="+filepath.Join(certDir, "client.crt"),
		"ETCDCTL_KEY="+filepath.Join(certDir, "client.key"),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("etcdctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	if len(output) > 1<<20 {
		return nil, fmt.Errorf("etcdctl response exceeds 1 MiB")
	}
	return output, nil
}

// ReadLocalEtcdMembership makes an authenticated linearizable member-list
// request through K3s's bundled etcdctl. Embedded etcd speaks gRPC; using its
// own client avoids assuming that an HTTP/JSON gateway is enabled.
func ReadLocalEtcdMembership(ctx context.Context, k3sDataDir string, inventory clustertopology.Inventory) InventoryHealth {
	if err := inventory.Validate(); err != nil {
		return InventoryHealth{Checked: true, Message: err.Error()}
	}
	if !filepath.IsAbs(k3sDataDir) {
		return InventoryHealth{Checked: true, Message: "K3s data directory must be absolute"}
	}
	body, err := etcdctlRun(ctx, k3sDataDir, "--endpoints="+localEtcdEndpoint, "member", "list", "--write-out=json")
	if err != nil {
		return InventoryHealth{Checked: true, Message: "query local etcd membership: " + err.Error()}
	}
	membership := ValidateEtcdMemberList(body, inventory)
	if !membership.Healthy {
		return membership
	}
	endpoints := make([]string, 0, len(inventory.Nodes))
	for _, node := range inventory.Nodes {
		endpoints = append(endpoints, "https://"+node.Address+":2379")
	}
	health, err := etcdctlRun(ctx, k3sDataDir, "--endpoints="+strings.Join(endpoints, ","), "endpoint", "health")
	if err != nil {
		return InventoryHealth{Checked: true, Message: "etcd peer health check failed: " + err.Error()}
	}
	for _, endpoint := range endpoints {
		if !strings.Contains(string(health), endpoint+" is healthy") {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("etcd peer %q did not report healthy", endpoint)}
		}
	}
	membership.Message += "; all three peers respond healthy over the planned server network"
	return membership
}

// ValidateEtcdMemberList matches exactly three voting etcd peers to the
// inventory's server addresses. A linearizable response means this list was
// confirmed through quorum; Kubernetes node readiness is checked separately.
func ValidateEtcdMemberList(body []byte, inventory clustertopology.Inventory) InventoryHealth {
	if err := inventory.Validate(); err != nil {
		return InventoryHealth{Checked: true, Message: err.Error()}
	}
	var response struct {
		Header struct {
			ClusterID json.RawMessage `json:"cluster_id"`
		} `json:"header"`
		Members []struct {
			ID         json.RawMessage `json:"ID"`
			Name       string          `json:"name"`
			PeerURLs   []string        `json:"peerURLs"`
			ClientURLs []string        `json:"clientURLs"`
			IsLearner  bool            `json:"isLearner"`
		} `json:"members"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return InventoryHealth{Checked: true, Message: fmt.Sprintf("decode etcd member list: %v", err)}
	}
	if _, err := positiveUint(response.Header.ClusterID); err != nil {
		return InventoryHealth{Checked: true, Message: "etcd member list has no valid cluster ID"}
	}
	if len(response.Members) != 3 {
		return InventoryHealth{Checked: true, Message: fmt.Sprintf("expected exactly three etcd members, observed %d", len(response.Members))}
	}
	expected := make(map[string]string, 3)
	for _, node := range inventory.Nodes {
		expected[node.Address] = node.Name
	}
	seenIDs := make(map[uint64]struct{}, 3)
	seenAddresses := make(map[string]struct{}, 3)
	for _, member := range response.Members {
		id, err := positiveUint(member.ID)
		if err != nil {
			return InventoryHealth{Checked: true, Message: "etcd member has no valid ID"}
		}
		if _, duplicate := seenIDs[id]; duplicate {
			return InventoryHealth{Checked: true, Message: "etcd member IDs are duplicated"}
		}
		seenIDs[id] = struct{}{}
		if member.IsLearner || strings.TrimSpace(member.Name) == "" || len(member.ClientURLs) == 0 || len(member.PeerURLs) != 1 {
			return InventoryHealth{Checked: true, Message: "etcd member is a learner, unstarted, or has unexpected peer URLs"}
		}
		peer, err := url.Parse(member.PeerURLs[0])
		if err != nil || peer.Scheme != "https" || peer.Port() != "2380" || peer.Path != "" || peer.RawQuery != "" {
			return InventoryHealth{Checked: true, Message: "etcd member has an invalid peer URL"}
		}
		if _, planned := expected[peer.Hostname()]; !planned {
			return InventoryHealth{Checked: true, Message: fmt.Sprintf("etcd peer %q is not in the planned server network", peer.Hostname())}
		}
		if _, duplicate := seenAddresses[peer.Hostname()]; duplicate {
			return InventoryHealth{Checked: true, Message: "multiple etcd members advertise the same peer address"}
		}
		seenAddresses[peer.Hostname()] = struct{}{}
	}
	return InventoryHealth{Checked: true, Healthy: true, Message: "three voting embedded-etcd members match the planned server addresses through a linearizable member-list response"}
}

func positiveUint(raw json.RawMessage) (uint64, error) {
	value := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("invalid unsigned ID")
	}
	return parsed, nil
}
