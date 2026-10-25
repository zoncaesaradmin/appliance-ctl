package install

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/bundle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/cluster"
	"github.com/zoncaesaradmin/appliance-ctl/internal/clustertopology"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/host"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

type threeServerSource struct{ resolved Resolved }

func (s threeServerSource) Resolve(context.Context, string) (Resolved, []evidence.Check, error) {
	return s.resolved, nil, nil
}

func threeServerFixture(t *testing.T, nodeName string) (*Orchestrator, threeServerSource, EmbeddedEtcdStageOptions, *bool) {
	t.Helper()
	root := t.TempDir()
	inventoryPath := filepath.Join(root, "inventory.json")
	content := `{"topology":"embedded-etcd-v1","bootstrapNode":"server-a","nodes":[{"name":"server-a","address":"10.0.0.11"},{"name":"server-b","address":"10.0.0.12"},{"name":"server-c","address":"10.0.0.13"}]}`
	if err := os.WriteFile(inventoryPath, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(root, "bundle", "k3s")
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binaryPath, []byte("signed-k3s"), 0o750); err != nil {
		t.Fatal(err)
	}
	address := "10.0.0.11"
	if nodeName == "server-b" {
		address = "10.0.0.12"
	}
	detected, active := false, false
	ops := k3s.Ops{
		DetectService: func(string) (k3s.ServiceSignal, error) {
			return k3s.ServiceSignal{Detected: detected, Active: active}, nil
		},
		WriteConfig: k3s.WriteConfig, WriteUnit: func(path string, cfg k3s.UnitConfig) error {
			detected = true
			return k3s.WriteUnit(path, cfg)
		},
		InstallBinary: k3s.InstallBinary, EnsureKubectlSymlink: k3s.EnsureKubectlSymlink,
		EnableAndStart: func(string) error {
			active = true
			caPath := filepath.Join(root, "data", "k3s", "server", "tls", "server-ca.crt")
			if err := os.MkdirAll(filepath.Dir(caPath), 0o700); err != nil {
				return err
			}
			return os.WriteFile(caPath, []byte("test-ca"), 0o600)
		},
		Version: func(string) (string, error) { return "v1.30.4+k3s1", nil },
	}
	orch := &Orchestrator{
		K3s:            ops,
		LocalAddresses: func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr(address)}, nil },
		HelmRun: func(_ context.Context, _ string, args ...string) (string, error) {
			if strings.Join(args, " ") == "--kubeconfig "+optsKubeconfigPath(root)+" get node "+nodeName+" -o jsonpath={.metadata.uid}" {
				return "uid-" + nodeName, nil
			}
			return "", nil
		},
		DetectHost: func(host.Options) (host.Facts, error) {
			return host.Facts{OS: "ubuntu", OSVersion: "24.04", Arch: "amd64", KernelRelease: "6.8.0", CPUCount: 8, MemTotalBytes: 16 << 30, CgroupVersion: 2, UserNamespacesEnabled: true, IPv4ForwardingEnabled: true, DataDirFilesystem: "ext4", DataDirFreeBytes: 100 << 30, DataDirFreeInodes: 1_000_000, TimeSyncActive: true, Hostname: nodeName, HostnameResolvesInternally: true, PortsInUse: map[int]string{}}, nil
		},
		ImagesRun: func(context.Context, string, ...string) (string, error) { return "", nil },
	}
	source := threeServerSource{Resolved{BundleVersion: "2.4.0", ReleaseID: "release-1", EffectiveProfile: "core", HostBaseline: bundle.HostBaseline{OS: "ubuntu", OSVersion: "24.04", Arch: "amd64"}, Compatibility: bundle.Compatibility{K3sVersion: "v1.30.4+k3s1", DeploymentTopology: clustertopology.EmbeddedEtcdV1}, K3sBinaryPath: binaryPath}}
	opts := EmbeddedEtcdStageOptions{Options: Options{
		ApplianceName: "zon", ApplianceProfile: "core", DNSZone: "appliance.internal", ClusterInventoryPath: inventoryPath, NodeName: nodeName,
		InstalledStatePath: filepath.Join(root, "state", "installed-state.json"), K3sConfigPath: filepath.Join(root, "etc", "config.yaml"),
		K3sUnitPath: filepath.Join(root, "systemd", "k3s.service"), K3sBinaryDestPath: filepath.Join(root, "bin", "k3s"),
		K3sDataDir: filepath.Join(root, "data", "k3s"), KubeconfigPath: filepath.Join(root, "etc", "k3s.yaml"),
		KubectlSymlinkPath: filepath.Join(root, "bin", "kubectl"), K3sUnitName: "k3s.service",
	}, ServerTokenFilePath: filepath.Join(root, "etc", "server-token")}
	return orch, source, opts, &active
}

func optsKubeconfigPath(root string) string {
	return filepath.Join(root, "etc", "k3s.yaml")
}

func TestStageThreeServerBootstrapsWithoutClaimingInstallation(t *testing.T) {
	orch, source, opts, _ := threeServerFixture(t, "server-a")
	staged, _, err := orch.StageEmbeddedEtcd(context.Background(), source, opts)
	if err != nil {
		t.Fatal(err)
	}
	if staged.Phase != clustertopology.PhaseServerReady || staged.EnrollmentSignerFingerprint == "" {
		t.Fatalf("unexpected staged state: %+v", staged)
	}
	config, err := os.ReadFile(opts.K3sConfigPath)
	if err != nil || !strings.Contains(string(config), "cluster-init: true") {
		t.Fatalf("bootstrap K3s config missing cluster-init: %q, %v", config, err)
	}
	if _, err := os.Stat(opts.InstalledStatePath); !os.IsNotExist(err) {
		t.Fatalf("partial cluster wrote InstalledState: %v", err)
	}
	if _, _, err := orch.StageEmbeddedEtcd(context.Background(), source, opts); err != nil {
		t.Fatalf("same-input stage rerun failed: %v", err)
	}
	successor := source
	successor.resolved.ReleaseID = "release-2"
	successor.resolved.BundleVersion = "2.4.1"
	staged, _, err = orch.StageEmbeddedEtcd(context.Background(), successor, opts)
	if err != nil {
		t.Fatalf("same-substrate successor stage rerun failed: %v", err)
	}
	if staged.ReleaseID != "release-2" || staged.BundleVersion != "2.4.1" {
		t.Fatalf("successor release was not recorded: %+v", staged)
	}
}

func TestStageThreeServerJoinsOnlyWithSignedInventoryBoundEnrollment(t *testing.T) {
	orch, source, opts, _ := threeServerFixture(t, "server-b")
	inventory, err := clustertopology.Load(opts.ClusterInventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, _ := inventory.Fingerprint()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opts.SignerFingerprint = cluster.Fingerprint(public)
	opts.EnrollmentPath = filepath.Join(t.TempDir(), "server-b.enrollment")
	now := time.Now().UTC()
	caDigest := sha256.Sum256([]byte("test-ca"))
	enrollment := cluster.Enrollment{
		ClusterID: "cluster-1", ApplianceName: "zon", ApplianceProfile: "core", DNSZone: "appliance.internal", ControlPlaneNode: "server-a", NodeRole: "server",
		DeploymentTopology: clustertopology.EmbeddedEtcdV1, InventoryFingerprint: fingerprint,
		ReleaseID: "release-1", ReleaseVersion: "2.4.0", ControlEndpoint: inventory.BootstrapAPIEndpoint(),
		ClusterCAHash:    "sha256:" + hex.EncodeToString(caDigest[:]),
		ExpectedNodeName: "server-b", K3sToken: "K10server-token", TokenFingerprint: cluster.TokenFingerprint("K10server-token"),
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), Nonce: "nonce",
	}
	if err := enrollment.SignEmbeddedEtcd(private); err != nil {
		t.Fatal(err)
	}
	if err := cluster.WriteEnrollment(opts.EnrollmentPath, enrollment); err != nil {
		t.Fatal(err)
	}
	staged, _, err := orch.StageEmbeddedEtcd(context.Background(), source, opts)
	if err != nil {
		t.Fatal(err)
	}
	if staged.ClusterID != "cluster-1" || staged.Phase != clustertopology.PhaseJoined || staged.NodeUID != "uid-server-b" {
		t.Fatalf("unexpected peer state: %+v", staged)
	}
	config, _ := os.ReadFile(opts.K3sConfigPath)
	if !strings.Contains(string(config), `server: "https://10.0.0.11:6443"`) || strings.Contains(string(config), "cluster-init: true") {
		t.Fatalf("peer config is not a joining server: %s", config)
	}
	if token, err := os.ReadFile(opts.ServerTokenFilePath); err != nil || strings.TrimSpace(string(token)) != enrollment.K3sToken {
		t.Fatalf("protected join token mismatch: %v", err)
	}
	if info, err := os.Stat(opts.ServerTokenFilePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("join token permissions incorrect: %v, %v", info, err)
	}
	enrollment.InventoryFingerprint = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if err := enrollment.SignEmbeddedEtcd(private); err != nil {
		t.Fatal(err)
	}
	if err := cluster.WriteEnrollment(opts.EnrollmentPath, enrollment); err != nil {
		t.Fatal(err)
	}
	if _, _, err := orch.StageEmbeddedEtcd(context.Background(), source, opts); err == nil {
		t.Fatal("different inventory enrollment accepted on rerun")
	}
	enrollment.InventoryFingerprint = fingerprint
	enrollment.ClusterCAHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := enrollment.SignEmbeddedEtcd(private); err != nil {
		t.Fatal(err)
	}
	if err := cluster.WriteEnrollment(opts.EnrollmentPath, enrollment); err != nil {
		t.Fatal(err)
	}
	if _, _, err := orch.StageEmbeddedEtcd(context.Background(), source, opts); err == nil {
		t.Fatal("different joined K3s CA accepted on rerun")
	}
}

func TestEmbeddedEtcdClusterMembersSatisfyInstalledStateSchema(t *testing.T) {
	now := time.Now().UTC()
	installed := &state.InstalledState{
		SchemaVersion:       1,
		ApplianceInstanceID: "cluster-1",
		InstalledVersion:    "2.4.0",
		InstalledReleaseID:  "01J8QK3F9G7XA6P0V6ZC9N6R4T",
		ApplianceProfile:    "core",
		Components:          state.Components{K3sVersion: "v1.30.4+k3s1", ChartVersion: "2.4.0"},
		K3sOwnership:        state.K3sOwnership{Owned: true, OwnerApplianceVersion: "2.4.0"},
		LastOperation: state.Operation{
			Type: "install", Status: "completed", TransactionID: "txn-01J8QK4G8H9YB7Q1W7ZD0P7S5U",
			StartedAt: now, CompletedAt: &now,
		},
		CreatedAt: now,
		UpdatedAt: now,
		Cluster: &state.Cluster{
			ID: "cluster-1", Topology: state.TopologyMultiServer, DeploymentTopology: state.DeploymentTopologyEmbeddedEtcdV1,
			ControlPlaneNode: "server-a", IngressNode: "server-a",
			ControlEndpoint: "https://10.0.0.11:6443",
			Nodes: []state.ClusterNode{
				embeddedEtcdClusterNode("server-a", "uid-server-a"),
				embeddedEtcdClusterNode("server-b", "uid-server-b"),
				embeddedEtcdClusterNode("server-c", "uid-server-c"),
			},
		},
	}
	for _, node := range installed.Cluster.Nodes {
		if node.Role != state.NodeRoleControlPlane || len(node.Roles) != 1 || node.Roles[0] != state.NodeRoleControlPlane {
			t.Fatalf("embedded-etcd member %q has non-schema role: %+v", node.Name, node)
		}
	}
	if err := state.Save(filepath.Join(t.TempDir(), "installed-state.json"), installed); err != nil {
		t.Fatal(err)
	}
}

func TestFinalizeThreeServerRefusesIncompleteSubstrateBeforeInstallation(t *testing.T) {
	orch, source, stageOpts, _ := threeServerFixture(t, "server-a")
	if _, _, err := orch.StageEmbeddedEtcd(context.Background(), source, stageOpts); err != nil {
		t.Fatalf("stage bootstrap: %v", err)
	}

	// The fixture's runner deliberately does not return a three-node Kubernetes
	// list or healthy direct API responses. Finalization must stop at the
	// substrate gate rather than falling through to Install and writing an
	// appliance receipt from a one-server bootstrap.
	installed, _, err := orch.FinalizeEmbeddedEtcd(context.Background(), source, stageOpts.Options)
	if err == nil || !strings.Contains(err.Error(), "substrate not ready") {
		t.Fatalf("incomplete three-server substrate was accepted: installed=%+v err=%v", installed, err)
	}
	if installed != nil {
		t.Fatalf("finalize returned an installation despite failed gate: %+v", installed)
	}
	if _, err := os.Stat(stageOpts.InstalledStatePath); !os.IsNotExist(err) {
		t.Fatalf("failed finalization wrote installed-state: %v", err)
	}
	staged, err := clustertopology.LoadBootstrapState(filepath.Join(filepath.Dir(stageOpts.InstalledStatePath), "cluster-bootstrap-state.json"))
	if err != nil || staged == nil || staged.Phase != clustertopology.PhaseServerReady {
		t.Fatalf("failed finalization changed bootstrap staging state: staged=%+v err=%v", staged, err)
	}
}
