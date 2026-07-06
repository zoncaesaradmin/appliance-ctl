package install_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/host"
	"github.com/zoncaesaradmin/appliance-ctl/internal/install"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

// healthyHostFacts fakes a fully-qualified, healthy host so preflight
// (which is genuinely host-environment-dependent) does not block these
// orchestration tests on a dev machine or CI box that happens not to
// match the v1 baseline. The preflight evaluation logic itself is
// exercised for real; only host detection is faked.
func healthyHostFacts(host.Options) (host.Facts, error) {
	return host.Facts{
		OS:                         "ubuntu",
		OSVersion:                  "24.04",
		Arch:                       "amd64",
		KernelRelease:              "6.8.0-generic",
		CPUCount:                   8,
		MemTotalBytes:              16 * 1024 * 1024 * 1024,
		CgroupVersion:              2,
		UserNamespacesEnabled:      true,
		IPv4ForwardingEnabled:      true,
		DataDir:                    "/var/lib/appliance",
		DataDirFilesystem:          "ext4",
		DataDirFreeBytes:           100 * 1024 * 1024 * 1024,
		DataDirFreeInodes:          1_000_000,
		TimeSyncActive:             true,
		Hostname:                   "appliance.internal.example.com",
		HostnameResolvesInternally: true,
		PortsInUse:                 map[int]string{},
	}, nil
}

// fixtureEntry is one file the fixture bundle writes and describes in its
// manifest.
type fixtureEntry struct {
	relPath        string
	component      string
	content        string
	imageReference string
}

// buildFixtureBundle writes a minimal, internally consistent air-gap
// bundle: every file install.Install actually reads, a signed
// release-manifest.json describing them, and a valid detached signature.
func buildFixtureBundle(t *testing.T) (dir string, pub verify.PublicKey) {
	t.Helper()
	dir = t.TempDir()

	entries := []fixtureEntry{
		{"k3s/binary/k3s", "k3s-binary", "fake k3s binary bytes", ""},
		{"charts/appliance-chart-2.4.0.tgz", "chart", "fake chart bytes", ""},
		{"crds/argo-crds-3.5.2.yaml", "crds", "fake crd manifest bytes", ""},
		{"configuration/values.yaml", "configuration", "replicaCount: 1\n", ""},
		{"k3s/images/coredns.tar", "k3s-images", "fake coredns image tar", "docker.io/rancher/mirrored-coredns-coredns:1.11.3"},
		{"oci-images/control-plane.tar", "oci-images", "fake control-plane image tar", "internal/control-plane:2.4.0"},
	}

	var manifestEntries []map[string]any
	for _, e := range entries {
		full := filepath.Join(dir, e.relPath)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(e.content), 0o640); err != nil {
			t.Fatal(err)
		}
		digest, err := verify.Digest(full)
		if err != nil {
			t.Fatal(err)
		}
		me := map[string]any{
			"path":      e.relPath,
			"component": e.component,
			"digest":    digest,
			"sizeBytes": len(e.content),
		}
		if e.imageReference != "" {
			me["imageReference"] = e.imageReference
		}
		manifestEntries = append(manifestEntries, me)
	}

	doc := map[string]any{
		"schemaVersion": 1,
		"bundleVersion": "2.4.0",
		"releaseId":     "01J8QK3F9G7XA6P0V6ZC9N6R4T",
		"hostBaseline":  map[string]any{"os": "ubuntu", "osVersion": "24.04", "arch": "amd64"},
		"builtAt":       "2026-07-04T00:00:00Z",
		"compatibility": map[string]any{"k3sVersion": "v1.30.4+k3s1", "chartVersion": "2.4.0", "argoVersion": "3.5.2"},
		"signingKeyId":  "release-signing-key",
		"entries":       manifestEntries,
	}
	manifestBytes, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "release-manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o640); err != nil {
		t.Fatal(err)
	}

	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(privKey, manifestBytes)
	if err := os.WriteFile(filepath.Join(dir, "release-manifest.sig"), sig, 0o640); err != nil {
		t.Fatal(err)
	}

	return dir, verify.PublicKey{ID: "release-signing-key", Key: pubKey}
}

// fakeK3s simulates the K3s adapter without systemd, recording every call
// and optionally failing one named step.
type fakeK3s struct {
	detected       k3s.ServiceSignal
	failStep       string
	calls          []string
	stopCalls      int
	runningVersion string
}

func (f *fakeK3s) ops() k3s.Ops {
	return k3s.Ops{
		DetectService: func(unit string) (k3s.ServiceSignal, error) {
			f.calls = append(f.calls, "detect")
			return f.detected, nil
		},
		WriteConfig: func(path string, cfg k3s.Config) error {
			f.calls = append(f.calls, "write-config")
			if f.failStep == "write-config" {
				return errors.New("simulated write-config failure")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				return err
			}
			return os.WriteFile(path, []byte(cfg.Render()), 0o640)
		},
		WriteUnit: func(path string, unit k3s.UnitConfig) error {
			f.calls = append(f.calls, "write-unit")
			if f.failStep == "write-unit" {
				return errors.New("simulated write-unit failure")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				return err
			}
			return os.WriteFile(path, []byte(unit.Render()), 0o640)
		},
		InstallBinary: func(src, dest string) error {
			f.calls = append(f.calls, "install-binary")
			if f.failStep == "install-binary" {
				return errors.New("simulated install-binary failure")
			}
			data, err := os.ReadFile(src)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
				return err
			}
			return os.WriteFile(dest, data, 0o750)
		},
		EnableAndStart: func(unit string) error {
			f.calls = append(f.calls, "enable-and-start")
			if f.failStep == "enable-and-start" {
				return errors.New("simulated enable-and-start failure")
			}
			return nil
		},
		Stop: func(unit string) error {
			f.stopCalls++
			f.calls = append(f.calls, "stop")
			return nil
		},
		Version: func(path string) (string, error) {
			f.calls = append(f.calls, "version")
			return f.runningVersion, nil
		},
	}
}

// fakeCLI simulates ctr/helm/kubectl for the images and helm adapters.
type fakeCLI struct {
	failOn       map[string]bool // substring of the joined args -> fail
	kubectlNodes string          // `kubectl get nodes` output, for cluster-adoption tests
	kubectlPods  string          // `kubectl get pods` output, for cluster-adoption tests
	calls        []string
}

func (f *fakeCLI) Run(_ context.Context, name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)

	for substr, fail := range f.failOn {
		if fail && strings.Contains(call, substr) {
			return "", fmt.Errorf("simulated failure for %q", substr)
		}
	}

	if name == "ctr" && contains(args, "ls") {
		return "", nil // nothing pre-imported
	}
	if name == "kubectl" && contains(args, "nodes") {
		return f.kubectlNodes, nil
	}
	if name == "kubectl" && contains(args, "pods") {
		return f.kubectlPods, nil
	}
	return "", nil
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func baseOptions(t *testing.T, bundleDir string, pub verify.PublicKey) install.Options {
	t.Helper()
	stateDir := t.TempDir()
	return install.Options{
		ApplianceVersion:   "2.4.0",
		InstalledStatePath: filepath.Join(stateDir, "installed-state.json"),
		K3sConfigPath:      filepath.Join(stateDir, "k3s", "config.yaml"),
		K3sDataDir:         filepath.Join(stateDir, "k3s", "data"),
		K3sUnitPath:        filepath.Join(stateDir, "systemd", "k3s.service"),
		K3sBinaryDestPath:  filepath.Join(stateDir, "bin", "k3s"),
		K3sUnitName:        "k3s.service",
		KubeconfigPath:     filepath.Join(stateDir, "k3s.yaml"),
		NodeName:           "appliance-node",
		ChartReleaseName:   "appliance",
		ChartNamespace:     "appliance",
		TransactionID:      "txn-test-0000000000000000000000",
	}
}

func TestInstall_EndToEndSuccess(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts}

	installed, checks, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err != nil {
		t.Fatalf("expected a clean fixture bundle to install successfully, got: %v (checks: %+v)", err, checks)
	}
	if installed.InstalledVersion != "2.4.0" || !installed.K3sOwnership.Owned {
		t.Errorf("unexpected installed state: %+v", installed)
	}
	if len(checks) == 0 {
		t.Error("expected a non-empty evidence check list")
	}

	if _, err := os.Stat(opts.InstalledStatePath); err != nil {
		t.Errorf("expected installed-state to be persisted: %v", err)
	}
	if _, err := os.Stat(opts.K3sBinaryDestPath); err != nil {
		t.Errorf("expected k3s binary to be installed: %v", err)
	}

	// Round-trip through the real schema-validated loader too.
	reloaded, err := state.Load(opts.InstalledStatePath)
	if err != nil {
		t.Fatalf("persisted installed-state failed to reload: %v", err)
	}
	if reloaded.InstalledReleaseID != "01J8QK3F9G7XA6P0V6ZC9N6R4T" {
		t.Errorf("unexpected release ID: %s", reloaded.InstalledReleaseID)
	}

	var importCalls int
	for _, c := range fcli.calls {
		if strings.Contains(c, "image import") {
			importCalls++
		}
	}
	if importCalls != 2 {
		t.Errorf("expected 2 image import calls (k3s-images + oci-images), got %d: %v", importCalls, fcli.calls)
	}
}

// Conflict: an existing K3s service this appliance never installed must
// block install before any host mutation happens.
func TestInstall_RejectsUnrelatedCluster(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)
	opts.PriorInstallAttempted = false

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: true, Active: true}}
	fcli := &fakeCLI{}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts}

	_, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err == nil {
		t.Fatal("expected install to refuse an unrelated existing cluster")
	}
	for _, c := range fk3s.calls {
		if c == "write-config" || c == "install-binary" {
			t.Errorf("expected no host mutation before the ownership check rejects, got calls: %v", fk3s.calls)
		}
	}
}

// Adoption: a healthy existing K3s cluster running the exact target
// version, with no foreign workloads, is adopted automatically — no
// force flag needed, and K3s itself is left untouched.
func TestInstall_AutoAdoptsSafeExistingCluster(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)

	fk3s := &fakeK3s{
		detected:       k3s.ServiceSignal{Detected: true, Active: true},
		runningVersion: "v1.30.4+k3s1", // matches the fixture bundle's pinned K3s version
	}
	fcli := &fakeCLI{
		kubectlNodes: "node1   Ready    control-plane,master   10d   v1.30.4+k3s1\n",
		kubectlPods:  "kube-system\nappliance\n",
	}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts}

	installed, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err != nil {
		t.Fatalf("expected adoption of a safe existing cluster to succeed, got: %v", err)
	}
	if !installed.K3sOwnership.Owned {
		t.Error("expected the adopted cluster to be recorded as owned")
	}
	for _, c := range fk3s.calls {
		if c == "write-config" || c == "install-binary" || c == "enable-and-start" {
			t.Errorf("expected no K3s reinstall when the running version already matches the target, got calls: %v", fk3s.calls)
		}
	}
}

// Adoption requires --force-adopt when the existing cluster carries
// foreign workloads, and succeeds once given.
func TestInstall_ForceAdoptRequiredForForeignWorkloads(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)

	fk3s := &fakeK3s{
		detected:       k3s.ServiceSignal{Detected: true, Active: true},
		runningVersion: "v1.30.4+k3s1",
	}
	fcli := &fakeCLI{
		kubectlNodes: "node1   Ready    control-plane,master   10d   v1.30.4+k3s1\n",
		kubectlPods:  "kube-system\ncustomer-app\n",
	}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts}

	if _, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts); err == nil {
		t.Fatal("expected install to refuse a cluster with foreign workloads without --force-adopt")
	}

	opts.ForceAdopt = true
	if _, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts); err != nil {
		t.Fatalf("expected --force-adopt to allow adoption despite foreign workloads, got: %v", err)
	}
}

// Rollback: a chart apply failure must roll back the images it just
// imported and stop the K3s service it just started, and must never
// persist installed-state.
func TestInstall_RollsBackOnChartFailure(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{failOn: map[string]bool{"upgrade --install": true}}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts}

	_, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err == nil {
		t.Fatal("expected the simulated chart failure to fail the install")
	}
	if fk3s.stopCalls == 0 {
		t.Error("expected k3s to be stopped as part of rollback")
	}

	var rmCalls int
	for _, c := range fcli.calls {
		if strings.Contains(c, "image rm") {
			rmCalls++
		}
	}
	if rmCalls != 2 {
		t.Errorf("expected both newly-imported images to be rolled back, got %d rm calls: %v", rmCalls, fcli.calls)
	}

	if _, err := os.Stat(opts.InstalledStatePath); !os.IsNotExist(err) {
		t.Errorf("expected no installed-state to be persisted on failure, stat err=%v", err)
	}
}

// Missing/tampered bundle artifact must fail before any host mutation.
func TestInstall_TamperedBundleFailsClosed(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	if err := os.WriteFile(filepath.Join(dir, "charts", "appliance-chart-2.4.0.tgz"), []byte("tampered!"), 0o640); err != nil {
		t.Fatal(err)
	}
	opts := baseOptions(t, dir, pub)

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts}

	_, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err == nil {
		t.Fatal("expected a tampered bundle to fail closed")
	}
	if len(fk3s.calls) != 0 {
		t.Errorf("expected no k3s calls before bundle verification completes, got %v", fk3s.calls)
	}
}

// Egress-denied / no-remote-fallback: a full successful install must
// never touch the network. Every artifact comes from BundleDir on local
// disk, and every mutating call goes through the fake K3s/CLI adapters.
func TestInstall_RequiresNoNetworkAccess(t *testing.T) {
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("network access is not permitted in this test")
		},
	}
	t.Cleanup(func() { net.DefaultResolver = original })

	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts}

	if _, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts); err != nil {
		t.Fatalf("expected install to succeed offline, got: %v", err)
	}
}
