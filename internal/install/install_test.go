package install_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/host"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostagent"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdirs"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostpackages"
	"github.com/zoncaesaradmin/appliance-ctl/internal/install"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/metadatabundle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
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

func healthyHostFactsWithK3SPortsInUse(host.Options) (host.Facts, error) {
	facts, err := healthyHostFacts(host.Options{})
	if err != nil {
		return host.Facts{}, err
	}
	facts.PortsInUse = map[int]string{
		6443:  "k3s-server",
		10250: "k3s-server",
		8472:  "k3s-server",
	}
	return facts, nil
}

func ubuntu2204HostFacts(host.Options) (host.Facts, error) {
	facts, err := healthyHostFacts(host.Options{})
	if err != nil {
		return host.Facts{}, err
	}
	facts.OSVersion = "22.04"
	return facts, nil
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
	return buildFixtureBundleWithOptions(t, false, true)
}

func buildFixtureBundleWithArgo(t *testing.T, includeArgo bool) (dir string, pub verify.PublicKey) {
	t.Helper()
	return buildFixtureBundleWithOptions(t, includeArgo, true)
}

func buildFixtureBundleWithOptions(t *testing.T, includeArgo, includeHostPackages bool) (dir string, pub verify.PublicKey) {
	t.Helper()
	dir = t.TempDir()

	entries := []fixtureEntry{
		{"bin/zonctl-real", "appliance", "fake zonctl binary bytes", ""},
		{"bin/helm", "appliance", "fake helm binary bytes", ""},
		{"bin/appliance-host-agentd", "appliance", "fake host agent daemon bytes", ""},
		{"k3s/binary/k3s", "k3s-binary", "fake k3s binary bytes", ""},
		{"charts/appliance-chart-2.4.0.tgz", "chart", "fake chart bytes", ""},
		{"charts/appliance-registry-2.1.7.tgz", "chart", "fake registry chart bytes", ""},
		{"charts/appliance-dns-1.14.4.tgz", "chart", "fake dns chart bytes", ""},
		{"artifacts/appliance-metadata-bundle-2.4.0.0.tar.zst", "artifacts", "", ""},
		{"configuration/values.yaml", "configuration", "replicaCount: 1\nsecrets:\n  keysSecretName: appliance-keys\n", ""},
		{"k3s/images/coredns.tar", "k3s-images", "fake coredns image tar", "docker.io/rancher/mirrored-coredns-coredns:1.11.3"},
		{"oci-images/control-plane.tar", "oci-images", "fake control-plane image tar", "internal/control-plane:2.4.0"},
		{"oci-images/appliance-ui.tar", "oci-images", "fake appliance UI image tar", "internal/appliance-ui:2.4.0"},
		{"oci-images/appliance-host-agent.tar", "oci-images", "fake appliance host agent image tar", "registry.local/appliance-host-agent@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
		{"oci-images/workspace-provisioner.tar", "oci-images", "fake workspace provisioner image tar", "registry.local/workspace-provisioner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"oci-images/dev-build.tar", "oci-images", "fake dev-build builder image tar", "registry.local/dev-build@sha256:5ccdfda08e940614d030e377b75f048a55e3f61cbb0234294ad333f27afe222c"},
		{"oci-images/zot.tar", "oci-images", "fake zot image tar", "registry.local/zot@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		{"oci-images/appliance-coredns.tar", "oci-images", "fake appliance coredns image tar", "registry.local/coredns@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
	}
	if includeArgo {
		entries = append(entries,
			fixtureEntry{"charts/argo-workflows-chart-3.5.10.tgz", "chart", "fake argo chart bytes", ""},
			fixtureEntry{"kubernetes/crds/workflows.argoproj.io.yaml", "kubernetes-crds", "kind: CustomResourceDefinition\n", ""},
			fixtureEntry{"oci-images/argo-controller.tar", "oci-images", "fake argo controller image tar", "quay.io/argoproj/workflow-controller:v3.5.10"},
			fixtureEntry{"oci-images/argo-executor.tar", "oci-images", "fake argo executor image tar", "quay.io/argoproj/argoexec:v3.5.10"},
		)
	}
	if includeHostPackages {
		entries = append(entries,
			fixtureEntry{"host-packages/ubuntu/24.04/amd64/avahi-daemon.deb", "host-packages", "fake avahi deb", ""},
			fixtureEntry{"host-packages/ubuntu/24.04/amd64/hostapd.deb", "host-packages", "fake hostapd deb", ""},
			fixtureEntry{"host-packages/ubuntu/24.04/amd64/dnsmasq.deb", "host-packages", "fake dnsmasq deb", ""},
		)
	}

	var manifestEntries []map[string]any
	for _, e := range entries {
		full := filepath.Join(dir, e.relPath)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		content := []byte(e.content)
		if e.relPath == "artifacts/appliance-metadata-bundle-2.4.0.0.tar.zst" {
			if err := metadatabundle.WriteMinimalArchive(full, "2.4.0.0",
				"core", "builder", "storage", "landns", "storage-landns", "builder-landns", "builder-storage-landns",
			); err != nil {
				t.Fatal(err)
			}
			var readErr error
			content, readErr = os.ReadFile(full)
			if readErr != nil {
				t.Fatal(readErr)
			}
		} else if err := os.WriteFile(full, content, 0o640); err != nil {
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
			"sizeBytes": len(content),
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
		"compatibility": map[string]any{"k3sVersion": "v1.30.4+k3s1", "chartVersion": "2.4.0", "zotVersion": "2.1.7", "dnsVersion": "1.14.4"},
		"signingKeyId":  "release-signing-key",
		"entries":       manifestEntries,
	}
	if includeArgo {
		doc["compatibility"].(map[string]any)["argoVersion"] = "3.5.10"
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
	detected          k3s.ServiceSignal
	failStep          string
	calls             []string
	stopCalls         int
	cleanupCalls      int
	daemonReloadCalls int
	runningVersion    string
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
		WriteRegistries: func(path string, cfg k3s.RegistriesConfig) error {
			f.calls = append(f.calls, "write-registries")
			if f.failStep == "write-registries" {
				return errors.New("simulated write-registries failure")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				return err
			}
			body, err := cfg.Render()
			if err != nil {
				return err
			}
			return os.WriteFile(path, body, 0o600)
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
		Restart: func(unit string) error {
			f.calls = append(f.calls, "restart")
			if f.failStep == "restart" {
				return errors.New("simulated restart failure")
			}
			return nil
		},
		CleanupNodeNetwork: func(cniNetworkDir string, interfaceNames []string) error {
			f.cleanupCalls++
			f.calls = append(f.calls, "cleanup-node-network")
			if f.failStep == "cleanup-node-network" {
				return errors.New("simulated cleanup-node-network failure")
			}
			return nil
		},
		DaemonReload: func() error {
			f.daemonReloadCalls++
			f.calls = append(f.calls, "daemon-reload")
			return nil
		},
		Version: func(path string) (string, error) {
			f.calls = append(f.calls, "version")
			return f.runningVersion, nil
		},
		EnsureKubectlSymlink: func(k3sBinaryPath, kubectlPath string) error {
			f.calls = append(f.calls, "ensure-kubectl-symlink")
			if f.failStep == "ensure-kubectl-symlink" {
				return errors.New("simulated ensure-kubectl-symlink failure")
			}
			return nil
		},
		RemoveKubectlSymlink: func(k3sBinaryPath, kubectlPath string) error {
			f.calls = append(f.calls, "remove-kubectl-symlink")
			return nil
		},
	}
}

// fakeCLI simulates ctr/helm/kubectl for the images and helm adapters.
type fakeCLI struct {
	failOn         map[string]bool // substring of the joined args -> fail
	kubectlNodes   string          // `kubectl get nodes` output, for cluster-adoption tests
	kubectlPods    string          // `kubectl get pods` output, for cluster-adoption tests
	secretExists   bool
	lastHelmValues string
	helmValues     map[string]string
	importedImages []string
	calls          []string
}

func (f *fakeCLI) Run(_ context.Context, name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)

	for substr, fail := range f.failOn {
		if fail && strings.Contains(call, substr) {
			return "", fmt.Errorf("simulated failure for %q", substr)
		}
	}

	if name == "helm" {
		if valuesPath := valuesPathFromHelmCall(call); valuesPath != "" {
			if data, err := os.ReadFile(valuesPath); err == nil {
				f.lastHelmValues = string(data)
				if releaseName := helmReleaseNameFromCall(call); releaseName != "" {
					if f.helmValues == nil {
						f.helmValues = map[string]string{}
					}
					f.helmValues[releaseName] = string(data)
				}
			}
		}
	}

	if name == "ctr" && contains(args, "ls") {
		return strings.Join(f.importedImages, "\n"), nil
	}
	if name == "ctr" && contains(args, "import") {
		for _, ref := range installTestImageRefsForArchive(importPathArg(args)) {
			f.addImportedImage(ref)
		}
		return "", nil
	}
	if name == "kubectl" && contains(args, "get") && contains(args, "secret") && contains(args, "json") &&
		(strings.Contains(call, "appliance-keys") || strings.Contains(call, "registry_ed25519_private.key")) {
		seedFile := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize))
		payload, _ := json.Marshal(map[string]any{
			"data": map[string]string{
				"registry_ed25519_private.key": base64.StdEncoding.EncodeToString([]byte(seedFile)),
			},
		})
		return string(payload), nil
	}
	if name == "kubectl" && contains(args, "get") && contains(args, "secret") && contains(args, "json") &&
		(strings.Contains(call, "appliance-ca") || strings.Contains(call, "appliance-tls")) {
		return "", errors.New("simulated missing secret")
	}
	if name == "kubectl" && contains(args, "get") && contains(args, "secret") && contains(args, "json") &&
		strings.Contains(call, "appliance-registry-verification-key") {
		return "", errors.New("simulated missing secret")
	}
	if name == "kubectl" && contains(args, "get") && contains(args, "secret") && strings.Contains(call, "registry_ed25519_private.key") {
		seedFile := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize))
		return base64.StdEncoding.EncodeToString([]byte(seedFile)), nil
	}
	if name == "kubectl" && contains(args, "get") && contains(args, "secret") && strings.Contains(call, "registry_ed25519_public.pem") {
		return "", errors.New("simulated missing secret")
	}
	if name == "kubectl" && contains(args, "get") && contains(args, "secret") {
		if f.secretExists {
			return "", nil
		}
		return "", errors.New("simulated missing secret")
	}
	if name == "kubectl" && contains(args, "create") && contains(args, "secret") {
		f.secretExists = true
		return "", nil
	}
	if name == "kubectl" && contains(args, "delete") && contains(args, "secret") {
		f.secretExists = false
		return "", nil
	}
	if name == "kubectl" && contains(args, "nodes") {
		return f.kubectlNodes, nil
	}
	if name == "kubectl" && contains(args, "pods") {
		return f.kubectlPods, nil
	}
	if name == "kubectl" && contains(args, "storageclass") {
		return "storageclass.storage.k8s.io/local-path", nil
	}
	// available/ready/replicas jsonpath polls (coredns, local-path, appliance-dns, …)
	if name == "kubectl" && contains(args, "get") && contains(args, "deployment") {
		return "1", nil
	}
	if name == "kubectl" && contains(args, "get") && contains(args, "svc") && contains(args, "traefik") {
		return `{"spec":{"externalIPs":["10.42.0.1"]}}`, nil
	}
	if name == "kubectl" && contains(args, "patch") && contains(args, "svc") && contains(args, "traefik") {
		return "service/traefik patched", nil
	}
	return "", nil
}

func (f *fakeCLI) addImportedImage(ref string) {
	for _, existing := range f.importedImages {
		if existing == ref {
			return
		}
	}
	f.importedImages = append(f.importedImages, ref)
}

func importPathArg(args []string) string {
	for i := len(args) - 1; i >= 0; i-- {
		if !strings.HasPrefix(args[i], "-") {
			return args[i]
		}
	}
	return ""
}

func installTestImageRefsForArchive(path string) []string {
	switch filepath.Base(path) {
	case "coredns.tar":
		return []string{"docker.io/rancher/mirrored-coredns-coredns:1.11.3"}
	case "appliance-coredns.tar":
		return []string{"registry.local/coredns@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
	case "control-plane.tar":
		return []string{"internal/control-plane:2.4.0"}
	case "appliance-ui.tar":
		return []string{"internal/appliance-ui:2.4.0"}
	case "appliance-host-agent.tar":
		return []string{"registry.local/appliance-host-agent@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}
	case "workspace-provisioner.tar":
		return []string{"registry.local/workspace-provisioner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	case "dev-build.tar":
		return []string{"registry.local/dev-build@sha256:5ccdfda08e940614d030e377b75f048a55e3f61cbb0234294ad333f27afe222c"}
	case "zot.tar":
		return []string{"registry.local/zot@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	case "argo-controller.tar":
		return []string{"quay.io/argoproj/workflow-controller:v3.5.10"}
	case "argo-executor.tar":
		return []string{"quay.io/argoproj/argoexec:v3.5.10"}
	default:
		return nil
	}
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func valuesPathFromHelmCall(call string) string {
	fields := strings.Fields(call)
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "--values" {
			return fields[i+1]
		}
	}
	return ""
}

func helmReleaseNameFromCall(call string) string {
	fields := strings.Fields(call)
	for i := 0; i < len(fields)-2; i++ {
		if fields[i] == "upgrade" && fields[i+1] == "--install" {
			return fields[i+2]
		}
	}
	return ""
}

func baseOptions(t *testing.T, bundleDir string, pub verify.PublicKey) install.Options {
	t.Helper()
	stateDir := t.TempDir()
	return install.Options{
		ApplianceVersion:        "2.4.0",
		InstalledStatePath:      filepath.Join(stateDir, "installed-state.json"),
		K3sConfigPath:           filepath.Join(stateDir, "k3s", "config.yaml"),
		K3sDataDir:              filepath.Join(stateDir, "k3s", "data"),
		K3sUnitPath:             filepath.Join(stateDir, "systemd", "k3s.service"),
		K3sBinaryDestPath:       filepath.Join(stateDir, "bin", "k3s"),
		KubectlSymlinkPath:      filepath.Join(stateDir, "bin", "kubectl"),
		K3sCNINetworkDir:        filepath.Join(stateDir, "cni", "networks", "cbr0"),
		K3sCNIInterfaces:        []string{"cni0", "flannel.1"},
		K3sUnitName:             "k3s.service",
		KubeconfigPath:          filepath.Join(stateDir, "k3s.yaml"),
		NodeName:                "appliance-node",
		ApplianceName:           "testapp",
		DNSZone:                 "appliance.internal",
		MetadataBundlesDir:      filepath.Join(stateDir, "metadata-bundles"),
		ZonctlRealDestPath:      filepath.Join(stateDir, "usr-local-lib", "zon", "bin", "zonctl-real"),
		ZonctlLauncherDestPath:  filepath.Join(stateDir, "usr-local-bin", "zonctl"),
		HostAgentBinaryDestPath: filepath.Join(stateDir, "usr-local-lib", "zon", "bin", "appliance-host-agentd"),
		HostAgentUnitPath:       filepath.Join(stateDir, "systemd", "zon-host-agent.service"),
		HostAgentUnitName:       "zon-host-agent.service",
		HostAgentSocketPath:     filepath.Join(stateDir, "run", "zon", "host-agent", "agent.sock"),
		HostAgentLogPath:        filepath.Join(stateDir, "logs", "host-agent", "host-agentd.log"),
		ChartReleaseName:        "appliance",
		ChartNamespace:          "control",
		TransactionID:           "txn-test-0000000000000000000000",
	}
}

func saveInstalledState(t *testing.T, path, installedVersion string) {
	t.Helper()
	now := time.Now().UTC()
	installed := &state.InstalledState{
		SchemaVersion:       1,
		ApplianceInstanceID: "test-instance",
		InstalledVersion:    installedVersion,
		InstalledReleaseID:  "prior-release",
		ApplianceProfile:    "core",
		ApplianceName:       "testapp",
		DNSZone:             "appliance.internal",
		Components:          state.Components{K3sVersion: "v1.30.4+k3s1", ChartVersion: installedVersion},
		K3sOwnership:        state.K3sOwnership{Owned: true, OwnerApplianceVersion: installedVersion},
		LastOperation: state.Operation{
			Type: "install", Status: "completed", TransactionID: "txn-prior",
			StartedAt: now, CompletedAt: &now,
		},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := state.Save(path, installed); err != nil {
		t.Fatal(err)
	}
}

func TestInstall_EndToEndSuccess(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n"}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

	installed, checks, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err != nil {
		t.Fatalf("expected a clean fixture bundle to install successfully, got: %v (checks: %+v)", err, checks)
	}
	if installed.InstalledVersion != "2.4.0" || !installed.K3sOwnership.Owned {
		t.Errorf("unexpected installed state: %+v", installed)
	}
	if installed.ApplianceProfile != "core" {
		t.Fatalf("appliance profile = %q, want core", installed.ApplianceProfile)
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
	if _, err := os.Stat(opts.ZonctlRealDestPath); err != nil {
		t.Errorf("expected host zonctl binary to be installed: %v", err)
	}
	if _, err := os.Stat(opts.ZonctlLauncherDestPath); err != nil {
		t.Errorf("expected host zonctl launcher to be installed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(opts.ZonctlRealDestPath), "helm")); err != nil {
		t.Errorf("expected durable host helm helper to be installed: %v", err)
	}

	// Round-trip through the real schema-validated loader too.
	reloaded, err := state.Load(opts.InstalledStatePath)
	if err != nil {
		t.Fatalf("persisted installed-state failed to reload: %v", err)
	}
	if reloaded.InstalledReleaseID != "01J8QK3F9G7XA6P0V6ZC9N6R4T" {
		t.Errorf("unexpected release ID: %s", reloaded.InstalledReleaseID)
	}
	if reloaded.ApplianceProfile != "core" {
		t.Fatalf("reloaded appliance profile = %q, want core", reloaded.ApplianceProfile)
	}

	var importCalls int
	var secretCreateCalls int
	for _, c := range fcli.calls {
		if strings.Contains(c, "image import") {
			importCalls++
		}
		if strings.Contains(c, "create secret generic appliance-keys") {
			secretCreateCalls++
		}
	}
	if importCalls != 6 {
		t.Errorf("expected 6 image import calls (k3s platform + control-plane app + UI app + host agent + workspace provisioner + dev-build), got %d: %v", importCalls, fcli.calls)
	}
	if secretCreateCalls != 1 {
		t.Errorf("expected installer-managed keys secret to be created once, got %d: %v", secretCreateCalls, fcli.calls)
	}
}

func TestInstall_StagesHostPackagesWithoutEnablingServices(t *testing.T) {
	dir, pub := buildFixtureBundleWithOptions(t, false, true)
	opts := baseOptions(t, dir, pub)

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n"}
	var packagesCalled bool
	var gotSpec hostpackages.InstallSpec
	orch := &install.Orchestrator{
		K3s:        fk3s.ops(),
		ImagesRun:  fcli.Run,
		HelmRun:    fcli.Run,
		ClusterRun: fcli.Run,
		DetectHost: healthyHostFacts,
		EnsureOwnedDir: func(string, int, int, os.FileMode) error {
			return nil
		},
		InstallHostPackages: func(spec hostpackages.InstallSpec) (func() error, error) {
			packagesCalled = true
			gotSpec = spec
			if spec.ServiceName != "" {
				t.Fatalf("package staging must not enable a service, got %q", spec.ServiceName)
			}
			return func() error { return nil }, nil
		},
		InstallHostAgent: func(hostagent.InstallSpec) (func() error, error) {
			return func() error { return nil }, nil
		},
	}

	_, checks, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err != nil {
		t.Fatalf("expected install to stage host packages, got: %v", err)
	}
	if !packagesCalled {
		t.Fatal("expected host packages install")
	}
	wantRoot := filepath.Join(dir, "host-packages")
	if gotSpec.RootDir != wantRoot {
		t.Fatalf("InstallHostPackages root = %q, want %q", gotSpec.RootDir, wantRoot)
	}
	var sawPackages, sawWifi, sawMDNS bool
	for _, check := range checks {
		switch check.ID {
		case "host-packages-installed":
			sawPackages = true
			if strings.Contains(check.Message, "enabled avahi") {
				t.Fatalf("install must not enable mDNS: %q", check.Message)
			}
		case "host-wifi-ap-applied", "host-mdns-installed":
			if check.ID == "host-wifi-ap-applied" {
				sawWifi = true
			}
			if check.ID == "host-mdns-installed" {
				sawMDNS = true
			}
		}
	}
	if !sawPackages {
		t.Fatal("expected host-packages-installed evidence")
	}
	if sawWifi || sawMDNS {
		t.Fatal("install must not enable mDNS or Wi-Fi AP (day-2 API only)")
	}
}

func TestInstall_LandnsAwaitsDNSWithoutWifiAP(t *testing.T) {
	dir, pub := buildFixtureBundleWithOptions(t, false, true)
	opts := baseOptions(t, dir, pub)
	opts.ApplianceProfile = "landns"

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n"}
	orch := &install.Orchestrator{
		K3s:        fk3s.ops(),
		ImagesRun:  fcli.Run,
		HelmRun:    fcli.Run,
		ClusterRun: fcli.Run,
		DetectHost: healthyHostFacts,
		EnsureOwnedDir: func(string, int, int, os.FileMode) error {
			return nil
		},
		InstallHostPackages: func(hostpackages.InstallSpec) (func() error, error) {
			return func() error { return nil }, nil
		},
		InstallHostAgent: func(hostagent.InstallSpec) (func() error, error) {
			return func() error { return nil }, nil
		},
	}

	_, checks, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err != nil {
		t.Fatalf("landns install: %v", err)
	}
	dnsHelmIdx, dnsReadyIdx := -1, -1
	for i, check := range checks {
		switch check.ID {
		case "helm-release-appliance-dns":
			if check.Status == evidence.StatusPass {
				dnsHelmIdx = i
			}
		case "appliance-dns-ready":
			if check.Status == evidence.StatusPass {
				dnsReadyIdx = i
			}
		case "host-wifi-ap-applied":
			t.Fatalf("landns install must not apply wifi-ap: %+v", check)
		}
	}
	if dnsHelmIdx < 0 {
		t.Fatalf("missing helm-release-appliance-dns pass: %+v", checks)
	}
	if dnsReadyIdx < 0 {
		t.Fatalf("missing appliance-dns-ready pass: %+v", checks)
	}
	if !(dnsHelmIdx < dnsReadyIdx) {
		t.Fatalf("expected DNS helm before ready, got helm=%d ready=%d", dnsHelmIdx, dnsReadyIdx)
	}
	var sawDNSDeploy bool
	for _, call := range fcli.calls {
		if strings.Contains(call, "get deployment dns-server") || (strings.Contains(call, "deployment") && strings.Contains(call, "dns-server")) {
			sawDNSDeploy = true
			break
		}
	}
	if !sawDNSDeploy {
		t.Fatalf("expected kubectl get deployment dns-server wait; calls=%v", fcli.calls)
	}
}

func TestInstall_InstallsHostPackagesForCoreProfile(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)
	opts.ApplianceProfile = "core"

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n"}
	var called bool
	orch := &install.Orchestrator{
		K3s:        fk3s.ops(),
		ImagesRun:  fcli.Run,
		HelmRun:    fcli.Run,
		ClusterRun: fcli.Run,
		DetectHost: healthyHostFacts,
		EnsureOwnedDir: func(string, int, int, os.FileMode) error {
			return nil
		},
		InstallHostPackages: func(spec hostpackages.InstallSpec) (func() error, error) {
			called = true
			if spec.ServiceName != "" {
				t.Fatalf("core profile install must not enable services, ServiceName=%q", spec.ServiceName)
			}
			if !strings.Contains(spec.RootDir, "host-packages") {
				t.Fatalf("RootDir = %q", spec.RootDir)
			}
			return func() error { return nil }, nil
		},
		InstallHostAgent: func(hostagent.InstallSpec) (func() error, error) {
			return func() error { return nil }, nil
		},
	}
	_, checks, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !called {
		t.Fatal("core profile must install host packages (mdns+wifi-ap debs) without enabling services")
	}
	var saw bool
	for _, check := range checks {
		if check.ID == "host-packages-installed" {
			saw = true
			if !strings.Contains(check.Message, "day-2") {
				t.Fatalf("unexpected evidence message: %q", check.Message)
			}
		}
	}
	if !saw {
		t.Fatal("expected host-packages-installed evidence")
	}
}

func TestInstall_InstallsBundledHostPackages(t *testing.T) {
	dir, pub := buildFixtureBundleWithOptions(t, false, true)
	opts := baseOptions(t, dir, pub)

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n"}
	var called bool
	var gotSpecRoot string
	orch := &install.Orchestrator{
		K3s:        fk3s.ops(),
		ImagesRun:  fcli.Run,
		HelmRun:    fcli.Run,
		ClusterRun: fcli.Run,
		DetectHost: healthyHostFacts,
		EnsureOwnedDir: func(string, int, int, os.FileMode) error {
			return nil
		},
		InstallHostPackages: func(spec hostpackages.InstallSpec) (func() error, error) {
			called = true
			gotSpecRoot = spec.RootDir
			if spec.OS != "ubuntu" || spec.OSVersion != "24.04" || spec.Arch != "amd64" {
				t.Fatalf("unexpected host package spec: %+v", spec)
			}
			if spec.ServiceName != "" {
				t.Fatalf("ServiceName = %q, want empty (no enable at install)", spec.ServiceName)
			}
			return func() error { return nil }, nil
		},
	}

	_, checks, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err != nil {
		t.Fatalf("expected host package install to succeed, got: %v", err)
	}
	if !called {
		t.Fatal("expected InstallHostPackages to be called")
	}
	wantRoot := filepath.Join(dir, "host-packages")
	if gotSpecRoot != wantRoot {
		t.Fatalf("InstallHostPackages root = %q, want %q", gotSpecRoot, wantRoot)
	}
	var sawEvidence bool
	for _, check := range checks {
		if check.ID == "host-packages-installed" {
			sawEvidence = true
			break
		}
	}
	if !sawEvidence {
		t.Fatal("expected host-packages-installed evidence check")
	}
}

func TestInstall_RefusesHostWhenBundleBaselineDoesNotMatch(t *testing.T) {
	dir, pub := buildFixtureBundleWithOptions(t, false, true)
	opts := baseOptions(t, dir, pub)

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n"}
	var installHostPackagesCalled bool
	orch := &install.Orchestrator{
		K3s:        fk3s.ops(),
		ImagesRun:  fcli.Run,
		HelmRun:    fcli.Run,
		ClusterRun: fcli.Run,
		DetectHost: ubuntu2204HostFacts,
		EnsureOwnedDir: func(string, int, int, os.FileMode) error {
			return nil
		},
		InstallHostPackages: func(hostpackages.InstallSpec) (func() error, error) {
			installHostPackagesCalled = true
			return func() error { return nil }, nil
		},
	}

	_, checks, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err == nil || !strings.Contains(err.Error(), "signed bundle baseline") {
		t.Fatalf("expected exact bundle baseline mismatch failure, got: %v", err)
	}
	if installHostPackagesCalled {
		t.Fatal("did not expect InstallHostPackages after a bundle baseline mismatch")
	}
	var sawMismatch bool
	for _, check := range checks {
		if check.ID == "bundle-host-baseline-match" && check.Status != "" {
			sawMismatch = true
			break
		}
	}
	if !sawMismatch {
		t.Fatalf("expected bundle-host-baseline-match evidence, got %+v", checks)
	}
	if len(fcli.calls) != 0 {
		t.Fatalf("expected no CLI mutations before baseline refusal, got %v", fcli.calls)
	}
}

func TestInstall_ClearsStaleInstalledStateWhenK3sArtifactsAreAbsent(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)
	saveInstalledState(t, opts.InstalledStatePath, "2.4.0")

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n"}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

	installed, checks, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err != nil {
		t.Fatalf("expected stale ownership-only state to be cleared and fresh install to proceed, got: %v", err)
	}
	if installed == nil || installed.InstalledVersion != "2.4.0" {
		t.Fatalf("expected installed state from the fresh install, got %+v", installed)
	}
	var sawCleanup bool
	for _, check := range checks {
		if check.ID == "k3s-stale-ownership-cleared" {
			sawCleanup = true
			break
		}
	}
	if !sawCleanup {
		t.Fatalf("expected stale ownership cleanup evidence, got checks: %+v", checks)
	}
}

func TestInstall_RefusesStaleInstalledStateWhenK3sArtifactsRemain(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)
	saveInstalledState(t, opts.InstalledStatePath, "2.4.0")
	if err := os.MkdirAll(filepath.Dir(opts.K3sConfigPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opts.K3sConfigPath, []byte("stale config"), 0o640); err != nil {
		t.Fatal(err)
	}

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n"}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

	if _, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts); err == nil || !strings.Contains(err.Error(), "requires-repair") {
		t.Fatalf("expected install to fail closed while K3s artifacts remain, got: %v", err)
	}
}

func TestInstall_PersistsAndPassesRequestedApplianceProfile(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)
	opts.ApplianceProfile = "builder"

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n"}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

	installed, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err != nil {
		t.Fatalf("expected install to succeed, got: %v", err)
	}
	if installed.ApplianceProfile != "builder" {
		t.Fatalf("appliance profile = %q, want builder", installed.ApplianceProfile)
	}

	if !strings.Contains(fcli.lastHelmValues, "applianceProfile: builder") {
		t.Fatalf("prepared values file missing builder profile: %s", fcli.lastHelmValues)
	}
}

func TestInstall_ArtifactProfileUsesApplianceIdentityForRegistry(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)
	opts.ApplianceProfile = "storage"
	opts.NodeName = "zonsyssrv1"
	opts.ApplianceName = "registry1"
	opts.DNSZone = "appliance.internal"
	opts.TLSSANs = []string{"192.168.1.101"}
	opts.TLSSANs = []string{"zonsyssrv1", "192.168.1.101"}

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n"}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

	if _, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts); err != nil {
		t.Fatalf("expected install to succeed, got: %v", err)
	}

	registryValues := fcli.helmValues["appliance-registry"]
	if !strings.Contains(registryValues, "realm: https://registry1.appliance.internal/api/v1/registry/token") {
		t.Fatalf("registry values missing realm override:\n%s", registryValues)
	}
	if strings.Contains(registryValues, "host: 192.168.1.101") {
		t.Fatalf("registry ingress host should remain empty by default so /v2 matches appliance IP access too:\n%s", registryValues)
	}
	if !strings.Contains(fcli.lastHelmValues, "canonicalOrigin: https://registry1.appliance.internal") {
		t.Fatalf("prepared values file missing canonical origin override:\n%s", fcli.lastHelmValues)
	}
	if strings.Contains(registryValues, "host: "+productconfig.DefaultLANDNSZone) {
		t.Fatalf("registry values should not fall back to %s:\n%s", productconfig.DefaultLANDNSZone, registryValues)
	}
}

// This is the exact production incident: a builder-profile host had
// /data/zon/workspaces created (e.g. by kubelet's hostPath
// DirectoryOrCreate) with the wrong owner, and a workflow pod hit
// "Permission denied" trying to mkdir inside it. Install must seed the
// correct owner itself, using the real hostdirs.EnsureOwnedDir logic
// (only the chown syscall is faked, since arbitrary chown targets
// require root).
func TestInstall_OwnsWorkspaceDirectoryForBuilderProfile(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)
	opts.ApplianceProfile = "builder"
	workspaceDir := filepath.Join(t.TempDir(), "workspaces")
	if err := os.MkdirAll(workspaceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	opts.WorkspaceRootDir = workspaceDir

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n"}
	ownedPaths := map[string][2]int{}
	ownedFiles := map[string][2]int{}
	var workspaceChowns [][2]int
	orch := &install.Orchestrator{
		K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts,
		EnsureOwnedDir: func(path string, uid, gid int, perm os.FileMode) error {
			if path != workspaceDir {
				ownedPaths[path] = [2]int{uid, gid}
				return nil
			}
			return hostdirs.EnsureOwnedDir(path, uid, gid, perm, func(_ string, u, g int) error {
				workspaceChowns = append(workspaceChowns, [2]int{u, g})
				return nil
			})
		},
		EnsureOwnedFile: func(path string, uid, gid int, perm os.FileMode) error {
			ownedFiles[path] = [2]int{uid, gid}
			if perm != hostdirs.ServiceLogFileMode {
				t.Fatalf("log file mode = %o, want %o", perm, hostdirs.ServiceLogFileMode)
			}
			return nil
		},
	}

	if _, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts); err != nil {
		t.Fatalf("expected install to succeed, got: %v", err)
	}

	if len(workspaceChowns) != 1 || workspaceChowns[0][0] != hostdirs.ApplianceDirOwnerUID || workspaceChowns[0][1] != hostdirs.ApplianceSharedFSGID {
		t.Fatalf("expected exactly one workspace chown to %d:%d, got %v", hostdirs.ApplianceDirOwnerUID, hostdirs.ApplianceSharedFSGID, workspaceChowns)
	}
	wantOwnedPaths := map[string][2]int{
		hostdirs.APIServerLogDir:      {hostdirs.ControlPlaneDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		hostdirs.UILogDir:             {hostdirs.UIDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		hostdirs.HostAgentLogDir:      {hostdirs.HostAgentDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		hostdirs.ArtifactServerLogDir: {hostdirs.RegistryDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		hostdirs.FileserverDir:        {hostdirs.ControlPlaneDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		hostdirs.ArgoControllerLogDir: {hostdirs.ArgoControllerDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		opts.MetadataBundlesDir:       {hostdirs.ControlPlaneDirOwnerUID, hostdirs.ApplianceSharedFSGID},
	}
	if len(ownedPaths) != len(wantOwnedPaths) {
		t.Fatalf("expected service log ownership for %v, got %v", wantOwnedPaths, ownedPaths)
	}
	for path, want := range wantOwnedPaths {
		if got, ok := ownedPaths[path]; !ok || got != want {
			t.Fatalf("expected service log ownership for %s to be %v, got %v (present=%t)", path, want, got, ok)
		}
	}
	wantOwnedFiles := map[string][2]int{
		hostdirs.HostAgentDaemonLog:           {0, hostdirs.ApplianceSharedFSGID},
		hostdirs.ArtifactServerApplicationLog: {hostdirs.RegistryDirOwnerUID, hostdirs.ApplianceSharedFSGID},
	}
	if len(ownedFiles) != len(wantOwnedFiles) {
		t.Fatalf("expected service log file ownership for %v, got %v", wantOwnedFiles, ownedFiles)
	}
	for path, want := range wantOwnedFiles {
		if got, ok := ownedFiles[path]; !ok || got != want {
			t.Fatalf("expected service log file ownership for %s to be %v, got %v (present=%t)", path, want, got, ok)
		}
	}
	info, err := os.Stat(workspaceDir)
	if err != nil {
		t.Fatal(err)
	}
	// The setgid bit itself can't be verified here: the kernel silently
	// strips it on chmod unless the calling process is root or already a
	// member of the target group (verified by hand: "chmod 2777" as a
	// non-root, non-member user fails the same way), which is exactly
	// the unprivileged posture this test runs under. Permission bits are
	// unaffected by that restriction and are what's checked here; setgid
	// takes effect for real once zonctl runs as root on the target host.
	if info.Mode().Perm() != hostdirs.WorkspaceDirMode.Perm() {
		t.Errorf("expected the pre-existing directory's mode to be corrected to %o, got %o", hostdirs.WorkspaceDirMode.Perm(), info.Mode().Perm())
	}
}

// Core profile still runs the control plane, UI, and workflow controller, so
// zonctl must seed those host-visible log directories itself, but it must not
// create builder-only workspace storage.
func TestInstall_CoreProfileOwnsOnlyServiceLogDirectories(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)
	opts.WorkspaceRootDir = filepath.Join(t.TempDir(), "workspaces")

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n"}
	ownedPaths := map[string][2]int{}
	orch := &install.Orchestrator{
		K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts,
		EnsureOwnedDir: func(path string, uid, gid int, _ os.FileMode) error {
			ownedPaths[path] = [2]int{uid, gid}
			return nil
		},
	}

	if _, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts); err != nil {
		t.Fatalf("expected install to succeed, got: %v", err)
	}
	wantOwnedPaths := map[string][2]int{
		hostdirs.APIServerLogDir:      {hostdirs.ControlPlaneDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		hostdirs.UILogDir:             {hostdirs.UIDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		hostdirs.HostAgentLogDir:      {hostdirs.HostAgentDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		hostdirs.ArgoControllerLogDir: {hostdirs.ArgoControllerDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		opts.MetadataBundlesDir:       {hostdirs.ControlPlaneDirOwnerUID, hostdirs.ApplianceSharedFSGID},
	}
	if len(ownedPaths) != len(wantOwnedPaths) {
		t.Fatalf("expected only core service log ownership %v, got %v", wantOwnedPaths, ownedPaths)
	}
	for path, want := range wantOwnedPaths {
		if got, ok := ownedPaths[path]; !ok || got != want {
			t.Fatalf("expected ownership for %s to be %v, got %v (present=%t)", path, want, got, ok)
		}
	}
	if _, err := os.Stat(opts.WorkspaceRootDir); !os.IsNotExist(err) {
		t.Error("expected the workspace directory to not be created for a non-builder profile")
	}
}

func TestInstall_StorageProfileOwnsArtifactServiceLogDirectoriesOnly(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)
	opts.ApplianceProfile = "storage"
	opts.WorkspaceRootDir = filepath.Join(t.TempDir(), "workspaces")

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n"}
	ownedPaths := map[string][2]int{}
	orch := &install.Orchestrator{
		K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts,
		EnsureOwnedDir: func(path string, uid, gid int, _ os.FileMode) error {
			ownedPaths[path] = [2]int{uid, gid}
			return nil
		},
	}

	if _, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts); err != nil {
		t.Fatalf("expected storage-profile install to succeed, got: %v", err)
	}
	wantOwnedPaths := map[string][2]int{
		hostdirs.APIServerLogDir:      {hostdirs.ControlPlaneDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		hostdirs.UILogDir:             {hostdirs.UIDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		hostdirs.HostAgentLogDir:      {hostdirs.HostAgentDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		hostdirs.ArtifactServerLogDir: {hostdirs.RegistryDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		hostdirs.FileserverDir:        {hostdirs.ControlPlaneDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		opts.MetadataBundlesDir:       {hostdirs.ControlPlaneDirOwnerUID, hostdirs.ApplianceSharedFSGID},
	}
	if len(ownedPaths) != len(wantOwnedPaths) {
		t.Fatalf("expected only storage service log ownership %v, got %v", wantOwnedPaths, ownedPaths)
	}
	for path, want := range wantOwnedPaths {
		if got, ok := ownedPaths[path]; !ok || got != want {
			t.Fatalf("expected ownership for %s to be %v, got %v (present=%t)", path, want, got, ok)
		}
	}
	if _, ok := ownedPaths[hostdirs.ArgoControllerLogDir]; ok {
		t.Fatalf("storage profile must not prepare %s: %v", hostdirs.ArgoControllerLogDir, ownedPaths)
	}
	if _, err := os.Stat(opts.WorkspaceRootDir); !os.IsNotExist(err) {
		t.Error("expected the workspace directory to not be created for the storage profile")
	}
}

func TestInstall_EndToEndSuccessWithOptionalArgoBringup(t *testing.T) {
	dir, pub := buildFixtureBundleWithArgo(t, true)
	opts := baseOptions(t, dir, pub)

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n"}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

	installed, checks, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err != nil {
		t.Fatalf("expected install with optional Argo artifacts to succeed, got: %v (checks: %+v)", err, checks)
	}
	if installed.InstalledVersion != "2.4.0" {
		t.Fatalf("unexpected installed state: %+v", installed)
	}

	var sawCRDApply bool
	var sawArgoHelm bool
	for _, c := range fcli.calls {
		if strings.Contains(c, "kubectl --kubeconfig") && strings.Contains(c, "apply -f") && strings.Contains(c, "workflows.argoproj.io.yaml") {
			sawCRDApply = true
		}
		if strings.Contains(c, "helm --kubeconfig") && strings.Contains(c, "upgrade --install argo-workflows") {
			sawArgoHelm = true
		}
	}
	if !sawCRDApply {
		t.Fatalf("expected Argo CRDs to be applied, got calls: %v", fcli.calls)
	}
	if !sawArgoHelm {
		t.Fatalf("expected Argo Helm release to be installed, got calls: %v", fcli.calls)
	}
}

func TestInstall_UsesBundleVersionForInstalledState(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)
	opts.ApplianceVersion = "v9.9.9"

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n"}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

	installed, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err != nil {
		t.Fatalf("expected install to succeed, got: %v", err)
	}
	if installed.InstalledVersion != "2.4.0" {
		t.Fatalf("expected installed version from bundle, got %s", installed.InstalledVersion)
	}
	if installed.K3sOwnership.OwnerApplianceVersion != "2.4.0" {
		t.Fatalf("expected ownership version from bundle, got %s", installed.K3sOwnership.OwnerApplianceVersion)
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
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

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
		kubectlPods:  "kube-system\ncontrol\n",
	}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

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

func TestInstall_RollsBackCreatedSecretWhenHelmFails(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{
		failOn:       map[string]bool{" upgrade --install ": true},
		kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n",
	}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

	_, checks, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err == nil {
		t.Fatal("expected simulated helm failure to abort install")
	}
	if len(checks) == 0 {
		t.Fatal("expected evidence checks on failure")
	}

	var sawCreateSecret bool
	var sawDeleteSecret bool
	for _, call := range fcli.calls {
		if strings.Contains(call, "create secret generic appliance-keys") {
			sawCreateSecret = true
		}
		if strings.Contains(call, "delete secret appliance-keys --ignore-not-found") {
			sawDeleteSecret = true
		}
	}
	if !sawCreateSecret {
		t.Fatalf("expected installer-managed keys secret creation before helm, got calls: %v", fcli.calls)
	}
	if !sawDeleteSecret {
		t.Fatalf("expected installer-managed keys secret rollback after helm failure, got calls: %v", fcli.calls)
	}
}

func TestInstall_RegistryFailureCollectsDiagnosticsAndRollsBack(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)
	opts.ApplianceProfile = "storage"

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{
		failOn:       map[string]bool{"upgrade --install appliance-registry": true},
		kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n",
	}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

	if _, checks, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts); err == nil {
		t.Fatal("expected simulated registry failure to abort install")
	} else if len(checks) == 0 {
		t.Fatal("expected failure diagnostics checks")
	}

	var sawStatus, sawDescribe, sawLogs, sawUninstall bool
	for _, call := range fcli.calls {
		sawStatus = sawStatus || strings.Contains(call, "helm --kubeconfig") && strings.Contains(call, "status appliance-registry")
		sawDescribe = sawDescribe || strings.Contains(call, "describe pods -l app.kubernetes.io/instance=appliance-registry")
		sawLogs = sawLogs || strings.Contains(call, "logs --all-containers=true --tail=200 -l app.kubernetes.io/instance=appliance-registry")
		sawUninstall = sawUninstall || strings.Contains(call, "helm --kubeconfig") && strings.Contains(call, "uninstall appliance-registry")
	}
	if !sawStatus || !sawDescribe || !sawLogs {
		t.Fatalf("expected registry diagnostics commands, got calls: %v", fcli.calls)
	}
	if !sawUninstall {
		t.Fatalf("expected fresh registry release uninstall on failure, got calls: %v", fcli.calls)
	}
	if fk3s.stopCalls == 0 {
		t.Fatal("expected rollback after registry failure to stop k3s")
	}
}

func TestInstall_AutoAdoptsSafeExistingClusterWhenK3SPortsAreAlreadyBound(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)

	fk3s := &fakeK3s{
		detected:       k3s.ServiceSignal{Detected: true, Active: true},
		runningVersion: "v1.30.4+k3s1",
	}
	fcli := &fakeCLI{
		kubectlNodes: "node1   Ready    control-plane,master   10d   v1.30.4+k3s1\n",
		kubectlPods:  "kube-system\ntraefik\ncontrol\n",
	}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFactsWithK3SPortsInUse, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

	installed, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err != nil {
		t.Fatalf("expected adoption of a safe existing cluster with K3s-owned ports already bound to succeed, got: %v", err)
	}
	if !installed.K3sOwnership.Owned {
		t.Error("expected the adopted cluster to be recorded as owned")
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
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

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
	fcli := &fakeCLI{
		failOn:       map[string]bool{"upgrade --install": true},
		kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n",
	}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

	_, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err == nil {
		t.Fatal("expected the simulated chart failure to fail the install")
	}
	if fk3s.stopCalls == 0 {
		t.Error("expected k3s to be stopped as part of rollback")
	}
	if fk3s.cleanupCalls == 0 {
		t.Error("expected stale K3s CNI state cleanup as part of rollback")
	}
	if fk3s.daemonReloadCalls == 0 {
		t.Error("expected a systemd daemon-reload as part of rollback, so a retried install doesn't see a stale 'existing K3s' signal")
	}
	for _, path := range []string{opts.K3sUnitPath, opts.K3sBinaryDestPath, opts.K3sConfigPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("expected %s to be removed as part of rollback, stat err=%v", path, err)
		}
	}

	var rmCalls int
	for _, c := range fcli.calls {
		if strings.Contains(c, "image rm") {
			rmCalls++
		}
	}
	if rmCalls != 6 {
		t.Errorf("expected all newly-imported images to be rolled back, got %d rm calls: %v", rmCalls, fcli.calls)
	}

	if _, err := os.Stat(opts.InstalledStatePath); !os.IsNotExist(err) {
		t.Errorf("expected no installed-state to be persisted on failure, stat err=%v", err)
	}
}

func TestInstall_PreserveFailedStateSkipsRollbackOnChartFailure(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)
	opts.PreserveFailedState = true

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{
		failOn:       map[string]bool{"upgrade --install": true},
		kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n",
	}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

	_, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err == nil {
		t.Fatal("expected the simulated chart failure to fail the install")
	}
	if !strings.Contains(err.Error(), "--preserve-failed-state") {
		t.Fatalf("expected error to mention preserved failed state, got: %v", err)
	}
	if fk3s.stopCalls != 0 {
		t.Errorf("expected no k3s stop during preserved failed state, got %d", fk3s.stopCalls)
	}
	// One CleanupNodeNetwork runs before K3s start (KillMode=process
	// orphan reap). Preserve-failed-state must not add a second cleanup
	// from rollback after the chart failure.
	if fk3s.cleanupCalls != 1 {
		t.Errorf("expected only the pre-start CNI/runtime cleanup during preserved failed state, got %d", fk3s.cleanupCalls)
	}
	if fk3s.daemonReloadCalls != 0 {
		t.Errorf("expected no daemon-reload during preserved failed state, got %d", fk3s.daemonReloadCalls)
	}
	if _, err := os.Stat(opts.K3sUnitPath); err != nil {
		t.Errorf("expected %s to remain for debugging: %v", opts.K3sUnitPath, err)
	}
	for _, c := range fcli.calls {
		if strings.Contains(c, "image rm") {
			t.Fatalf("expected imported images to remain during preserved failed state, got calls: %v", fcli.calls)
		}
	}
}

func TestInstall_RegistryFailurePreserveFailedStateSkipsRollback(t *testing.T) {
	dir, pub := buildFixtureBundle(t)
	opts := baseOptions(t, dir, pub)
	opts.ApplianceProfile = "storage"
	opts.PreserveFailedState = true

	fk3s := &fakeK3s{detected: k3s.ServiceSignal{Detected: false}}
	fcli := &fakeCLI{
		failOn:       map[string]bool{"upgrade --install appliance-registry": true},
		kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n",
	}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

	_, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts)
	if err == nil {
		t.Fatal("expected simulated registry failure to abort install")
	}
	if !strings.Contains(err.Error(), "--preserve-failed-state") {
		t.Fatalf("expected preserve-failed-state error, got: %v", err)
	}
	for _, call := range fcli.calls {
		if strings.Contains(call, "uninstall appliance-registry") || strings.Contains(call, "image rm") {
			t.Fatalf("expected registry failure state to be preserved, got calls: %v", fcli.calls)
		}
	}
	if fk3s.stopCalls != 0 {
		t.Fatalf("expected no k3s stop when preserving failed registry state, got %d", fk3s.stopCalls)
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
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

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
	fcli := &fakeCLI{kubectlNodes: "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n"}
	orch := &install.Orchestrator{K3s: fk3s.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run, ClusterRun: fcli.Run, DetectHost: healthyHostFacts, EnsureOwnedDir: func(string, int, int, os.FileMode) error { return nil }}

	if _, _, err := orch.Install(context.Background(), install.OfflineSource{BundleDir: dir, PublicKey: &pub}, opts); err != nil {
		t.Fatalf("expected install to succeed offline, got: %v", err)
	}
}
