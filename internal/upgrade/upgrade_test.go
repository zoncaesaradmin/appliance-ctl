package upgrade_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/host"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostagent"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdirs"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostpackages"
	"github.com/zoncaesaradmin/appliance-ctl/internal/install"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/metadatabundle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
	"github.com/zoncaesaradmin/appliance-ctl/internal/upgrade"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

type bundleSpec struct {
	bundleVersion    string
	k3sVersion       string
	chartVersion     string
	supportedSources []string
	includeWorkflows bool
	profiles         map[string][]string
}

func healthyUpgradeHostFacts(host.Options) (host.Facts, error) {
	return host.Facts{OS: "ubuntu", OSVersion: "24.04", Arch: "amd64"}, nil
}

func ubuntu2204UpgradeHostFacts(host.Options) (host.Facts, error) {
	return host.Facts{OS: "ubuntu", OSVersion: "22.04", Arch: "amd64"}, nil
}

func newUpgradeOrchestrator(fake *fakeK3s, fcli *fakeCLI) *upgrade.Orchestrator {
	return &upgrade.Orchestrator{
		K3s:        fake.ops(),
		ImagesRun:  fcli.Run,
		HelmRun:    fcli.Run,
		DetectHost: healthyUpgradeHostFacts,
		EnsureOwnedDir: func(string, int, int, os.FileMode) error {
			return nil
		},
	}
}

func buildBundle(t *testing.T, spec bundleSpec) (dir string, pub verify.PublicKey) {
	t.Helper()
	dir = t.TempDir()

	entries := []struct {
		relPath        string
		component      string
		content        string
		imageReference string
	}{
		{"bin/zonctl-real", "appliance", "fake zonctl binary " + spec.bundleVersion, ""},
		{"bin/helm", "appliance", "fake helm binary " + spec.bundleVersion, ""},
		{"bin/appliance-host-agentd", "appliance", "fake host agent daemon " + spec.bundleVersion, ""},
		{"k3s/binary/k3s", "k3s-binary", "fake k3s binary " + spec.k3sVersion, ""},
		{"charts/appliance-chart.tgz", "chart", "fake chart " + spec.chartVersion, ""},
		{"charts/appliance-registry-2.1.7.tgz", "chart", "fake registry chart", ""},
		{"charts/appliance-dns-1.14.4.tgz", "chart", "fake dns chart", ""},
		{"charts/appliance-inference-0.6.5.tgz", "chart", "fake inference chart", ""},
		{"artifacts/appliance-metadata-bundle-2.4.0.0.tar.zst", "artifacts", "", ""},
		{"configuration/values.yaml", "configuration", "replicaCount: 1\nsecrets:\n  keysSecretName: appliance-keys\n", ""},
		{"oci-images/control-plane.tar", "oci-images", "fake control-plane image " + spec.bundleVersion, "internal/control-plane:" + spec.bundleVersion},
		{"oci-images/appliance-ui.tar", "oci-images", "fake appliance UI image " + spec.bundleVersion, "internal/appliance-ui:" + spec.bundleVersion},
		{"oci-images/appliance-host-agent.tar", "oci-images", "fake appliance host agent image " + spec.bundleVersion, "registry.local/appliance-host-agent@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
		{"oci-images/workspace-provisioner.tar", "oci-images", "fake workspace provisioner image " + spec.bundleVersion, "registry.local/workspace-provisioner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"oci-images/artifact-server.tar", "oci-images", "fake artifact server image " + spec.bundleVersion, "registry.local/artifact-server@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		{"oci-images/dns-server.tar", "oci-images", "fake dns-server image " + spec.bundleVersion, "registry.local/coredns@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
		{"oci-images/blob-storage.tar", "oci-images", "fake blob storage image " + spec.bundleVersion, "registry.local/blob-storage@sha256:abababababababababababababababababababababababababababababababab"},
		{"oci-images/inference-runtime.tar", "oci-images", "fake inference-runtime image " + spec.bundleVersion, "registry.local/inference-runtime@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
	}
	if spec.includeWorkflows {
		entries = append(entries,
			struct {
				relPath        string
				component      string
				content        string
				imageReference string
			}{"charts/workflows-chart-3.5.10.tgz", "chart", "fake workflows chart", ""},
			struct {
				relPath        string
				component      string
				content        string
				imageReference string
			}{"kubernetes/crds/workflows.argoproj.io.yaml", "kubernetes-crds", "kind: CustomResourceDefinition\n", ""},
			struct {
				relPath        string
				component      string
				content        string
				imageReference string
			}{"oci-images/workflow-controller.tar", "oci-images", "fake workflow-controller image", "quay.io/argoproj/workflow-controller:v3.5.10"},
			struct {
				relPath        string
				component      string
				content        string
				imageReference string
			}{"oci-images/workflow-executor.tar", "oci-images", "fake workflow executor image", "quay.io/argoproj/argoexec:v3.5.10"},
		)
	}
	entries = append(entries, struct {
		relPath        string
		component      string
		content        string
		imageReference string
	}{
		relPath: "host-packages/ubuntu/24.04/amd64/avahi-daemon.deb", component: "host-packages", content: "fake avahi deb",
	})

	var manifestEntries []map[string]any
	for _, e := range entries {
		full := filepath.Join(dir, e.relPath)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		content := []byte(e.content)
		if e.relPath == "artifacts/appliance-metadata-bundle-2.4.0.0.tar.zst" {
			var writeErr error
			if spec.profiles != nil {
				writeErr = metadatabundle.WriteProfileCatalogArchive(full, "2.4.0.0", spec.profiles)
			} else {
				writeErr = metadatabundle.WriteInstallTestArchive(full, "2.4.0.0")
			}
			if writeErr != nil {
				t.Fatal(writeErr)
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
		manifestEntries = append(manifestEntries, map[string]any{
			"path": e.relPath, "component": e.component, "digest": digest, "sizeBytes": len(content),
		})
		if e.imageReference != "" {
			manifestEntries[len(manifestEntries)-1]["imageReference"] = e.imageReference
		}
	}

	doc := map[string]any{
		"schemaVersion": 1,
		"bundleVersion": spec.bundleVersion,
		"releaseId":     "01J8QK3F9G7XA6P0V6ZC9N6R4T",
		"hostBaseline":  map[string]any{"os": "ubuntu", "osVersion": "24.04", "arch": "amd64"},
		"builtAt":       "2026-07-04T00:00:00Z",
		"compatibility": map[string]any{
			"k3sVersion": spec.k3sVersion, "chartVersion": spec.chartVersion,
			"artifactServerVersion":   "2.1.7",
			"dnsVersion":              "1.14.4",
			"inferenceVersion":        "0.6.5",
			"supportedUpgradeSources": spec.supportedSources,
		},
		"signingKeyId": "release-signing-key",
		"entries":      manifestEntries,
	}
	if spec.includeWorkflows {
		doc["compatibility"].(map[string]any)["workflowsVersion"] = "3.5.10"
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
	if err := os.WriteFile(filepath.Join(dir, "release-manifest.sig"), ed25519.Sign(privKey, manifestBytes), 0o640); err != nil {
		t.Fatal(err)
	}
	return dir, verify.PublicKey{ID: "release-signing-key", Key: pubKey}
}

type fakeK3s struct {
	failStep    string
	calls       []string
	lastTLSSANs []string
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

func (f *fakeK3s) ops() k3s.Ops {
	return k3s.Ops{
		DetectService: func(string) (k3s.ServiceSignal, error) {
			return k3s.ServiceSignal{Detected: true, Active: true}, nil
		},
		WriteConfig: func(path string, cfg k3s.Config) error {
			f.calls = append(f.calls, "write-config")
			f.lastTLSSANs = append([]string(nil), cfg.TLSSANs...)
			if f.failStep == "write-config" {
				return fmt.Errorf("simulated write-config failure")
			}
			return os.WriteFile(path, []byte(cfg.Render()), 0o640)
		},
		WriteRegistries: func(path string, cfg k3s.RegistriesConfig) error {
			f.calls = append(f.calls, "write-registries")
			body, err := cfg.Render()
			if err != nil {
				return err
			}
			return os.WriteFile(path, body, 0o600)
		},
		WriteUnit: func(path string, unit k3s.UnitConfig) error {
			f.calls = append(f.calls, "write-unit")
			return os.WriteFile(path, []byte(unit.Render()), 0o640)
		},
		InstallBinary: func(src, dest string) error {
			f.calls = append(f.calls, "install-binary")
			data, err := os.ReadFile(src)
			if err != nil {
				return err
			}
			return os.WriteFile(dest, data, 0o750)
		},
		EnableAndStart: func(string) error {
			f.calls = append(f.calls, "enable-and-start")
			return nil
		},
		Stop: func(string) error {
			f.calls = append(f.calls, "stop")
			return nil
		},
		Restart: func(string) error {
			f.calls = append(f.calls, "restart")
			return nil
		},
	}
}

// environment sets up a fully installed host: a fake data directory,
// current k3s binary/config/unit files, and an installed-state record.
type environment struct {
	stateDir           string
	dataDir            string
	k3sConfigPath      string
	k3sUnitPath        string
	k3sBinaryDestPath  string
	installedStatePath string
	backupRoot         string
	kubeconfigPath     string
}

func setupEnvironment(t *testing.T, installedVersion, k3sVersion, chartVersion, applianceProfile string) environment {
	t.Helper()
	stateDir := t.TempDir()
	env := environment{
		stateDir:           stateDir,
		dataDir:            filepath.Join(stateDir, "k3s-data"),
		k3sConfigPath:      filepath.Join(stateDir, "k3s", "config.yaml"),
		k3sUnitPath:        filepath.Join(stateDir, "systemd", "k3s.service"),
		k3sBinaryDestPath:  filepath.Join(stateDir, "bin", "k3s"),
		installedStatePath: filepath.Join(stateDir, "installed-state.json"),
		backupRoot:         filepath.Join(stateDir, "backups"),
		kubeconfigPath:     filepath.Join(stateDir, "k3s.yaml"),
	}

	for _, p := range []string{env.k3sConfigPath, env.k3sUnitPath, env.k3sBinaryDestPath} {
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("current "+filepath.Base(p)+" content"), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(env.dataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.dataDir, "state.db"), []byte("original k3s data"), 0o640); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	installed := &state.InstalledState{
		SchemaVersion:       1,
		ApplianceInstanceID: "test-instance",
		InstalledVersion:    installedVersion,
		InstalledReleaseID:  "prior-release",
		ApplianceProfile:    applianceProfile,
		ApplianceName:       "testapp",
		DNSZone:             "appliance.internal",
		Components:          state.Components{K3sVersion: k3sVersion, ChartVersion: chartVersion},
		K3sOwnership:        state.K3sOwnership{Owned: true, OwnerApplianceVersion: installedVersion},
		LastOperation: state.Operation{
			Type: "install", Status: "completed", TransactionID: "txn-prior",
			StartedAt: now, CompletedAt: &now,
		},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := state.Save(env.installedStatePath, installed); err != nil {
		t.Fatal(err)
	}
	return env
}

func (env environment) options(targetVersion string) upgrade.Options {
	return upgrade.Options{
		TargetApplianceVersion:  targetVersion,
		InstalledStatePath:      env.installedStatePath,
		K3sConfigPath:           env.k3sConfigPath,
		K3sUnitPath:             env.k3sUnitPath,
		K3sBinaryDestPath:       env.k3sBinaryDestPath,
		K3sUnitName:             "k3s.service",
		K3sDataDir:              env.dataDir,
		KubeconfigPath:          env.kubeconfigPath,
		NodeName:                "appliance-node",
		ApplianceName:           "testapp",
		DNSZone:                 "appliance.internal",
		MetadataBundlesDir:      filepath.Join(env.stateDir, "metadata-bundles"),
		ZonctlRealDestPath:      filepath.Join(env.stateDir, "usr-local-lib", "zon", "bin", "zonctl-real"),
		ZonctlLauncherDestPath:  filepath.Join(env.stateDir, "usr-local-bin", "zonctl"),
		HostAgentBinaryDestPath: filepath.Join(env.stateDir, "usr-local-lib", "zon", "bin", "appliance-host-agentd"),
		HostAgentUnitPath:       filepath.Join(env.stateDir, "systemd", "zon-host-agent.service"),
		HostAgentUnitName:       "zon-host-agent.service",
		HostAgentSocketPath:     filepath.Join(env.stateDir, "run", "zon", "host-agent", "agent.sock"),
		HostAgentLogPath:        filepath.Join(env.stateDir, "logs", "host-agent", "host-agentd.log"),
		ChartReleaseName:        "appliance",
		ChartNamespace:          "ace-system",
		BackupRoot:              env.backupRoot,
		TransactionID:           "txn-upgrade-test",
	}
}

// Source-to-target matrix: every declared supported source version must
// upgrade successfully to the target.
func TestUpgrade_SupportedSourceMatrix(t *testing.T) {
	matrix := []string{"2.3.0", "2.3.1"}

	for _, source := range matrix {
		t.Run(source, func(t *testing.T) {
			env := setupEnvironment(t, source, "v1.30.0+k3s1", "2.3.0", "core")
			bundleDir, pub := buildBundle(t, bundleSpec{
				bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
				supportedSources: matrix,
			})

			fake := &fakeK3s{}
			fcli := &fakeCLI{}
			orch := newUpgradeOrchestrator(fake, fcli)

			offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
			updated, _, err := orch.Upgrade(context.Background(), offlineSource, env.options("2.4.0"))
			if err != nil {
				t.Fatalf("expected upgrade from %s to succeed, got: %v", source, err)
			}
			if updated.InstalledVersion != "2.4.0" || updated.LastOperation.SourceVersion != source {
				t.Errorf("unexpected result: %+v", updated)
			}
		})
	}
}

func TestUpgrade_UsesBundleVersionAsTargetVersion(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.0+k3s1", "2.3.0", "core")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{}
	orch := newUpgradeOrchestrator(fake, fcli)

	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	updated, _, err := orch.Upgrade(context.Background(), offlineSource, env.options("v9.9.9"))
	if err != nil {
		t.Fatalf("expected upgrade to succeed, got: %v", err)
	}
	if updated.InstalledVersion != "2.4.0" {
		t.Fatalf("expected installed version from bundle, got %s", updated.InstalledVersion)
	}
	if updated.LastOperation.TargetVersion != "2.4.0" {
		t.Fatalf("expected target version from bundle, got %s", updated.LastOperation.TargetVersion)
	}
}

func TestUpgrade_InstallsBundledHostPackages(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.0+k3s1", "2.3.0", "storage-landns")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{}
	var called bool
	var gotSpecRoot string
	orch := newUpgradeOrchestrator(fake, fcli)
	orch.InstallHostPackages = func(spec hostpackages.InstallSpec) (func() error, error) {
		called = true
		gotSpecRoot = spec.RootDir
		return func() error { return nil }, nil
	}

	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	opts := env.options("2.4.0")
	_, checks, err := orch.Upgrade(context.Background(), offlineSource, opts)
	if err != nil {
		t.Fatalf("expected upgrade to succeed, got: %v", err)
	}
	if !called {
		t.Fatal("expected InstallHostPackages to be called")
	}
	wantRoot := filepath.Join(bundleDir, "host-packages")
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

func TestUpgrade_RefusesHostWhenBundleBaselineDoesNotMatch(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.0+k3s1", "2.3.0", "core")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{}
	var installHostPackagesCalled bool
	orch := newUpgradeOrchestrator(fake, fcli)
	orch.DetectHost = ubuntu2204UpgradeHostFacts
	orch.InstallHostPackages = func(hostpackages.InstallSpec) (func() error, error) {
		installHostPackagesCalled = true
		return func() error { return nil }, nil
	}

	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	opts := env.options("2.4.0")
	_, checks, err := orch.Upgrade(context.Background(), offlineSource, opts)
	if err == nil || !strings.Contains(err.Error(), "signed bundle baseline") {
		t.Fatalf("expected exact bundle baseline mismatch failure, got: %v", err)
	}
	if installHostPackagesCalled {
		t.Fatal("did not expect InstallHostPackages after a bundle baseline mismatch")
	}
	var sawMismatch bool
	for _, check := range checks {
		if check.ID == "bundle-host-baseline-match" {
			sawMismatch = true
			break
		}
	}
	if !sawMismatch {
		t.Fatalf("expected bundle-host-baseline-match evidence, got %+v", checks)
	}
	if len(fake.calls) != 0 || len(fcli.calls) != 0 {
		t.Fatalf("expected no mutations before baseline refusal, got k3s=%v cli=%v", fake.calls, fcli.calls)
	}
}

func TestUpgrade_PreservesInstalledApplianceProfileWhenFlagOmitted(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.0+k3s1", "2.3.0", "storage")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{}
	orch := newUpgradeOrchestrator(fake, fcli)

	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	updated, _, err := orch.Upgrade(context.Background(), offlineSource, env.options("2.4.0"))
	if err != nil {
		t.Fatalf("expected upgrade to succeed, got: %v", err)
	}
	if updated.ApplianceProfile != "storage" {
		t.Fatalf("appliance profile = %q, want storage", updated.ApplianceProfile)
	}

	if !strings.Contains(fcli.lastHelmValues, "applianceProfile: storage") {
		t.Fatalf("prepared values file missing storage profile: %s", fcli.lastHelmValues)
	}
}

func TestUpgrade_HostProfileReenablesDefaultMDNS(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.0+k3s1", "2.3.0", "training")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
		profiles: map[string][]string{
			"training": {"base", "host", "files", "video"},
		},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{}
	orch := newUpgradeOrchestrator(fake, fcli)
	var installedHostAgent, enabledMDNS bool
	orch.InstallHostAgent = func(hostagent.InstallSpec) (func() error, error) {
		installedHostAgent = true
		return func() error { return nil }, nil
	}
	orch.EnsureMDNSEnabled = func(_ context.Context, socket string) error {
		if socket != env.options("2.4.0").HostAgentSocketPath {
			t.Fatalf("host-agent socket = %q", socket)
		}
		if !installedHostAgent {
			t.Fatal("mDNS enabled before host agent installation")
		}
		enabledMDNS = true
		return nil
	}

	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	_, checks, err := orch.Upgrade(context.Background(), offlineSource, env.options("2.4.0"))
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if !enabledMDNS {
		t.Fatal("expected host profile upgrade to enable default mDNS")
	}
	for _, check := range checks {
		if check.ID == "host-mdns-enabled" {
			return
		}
	}
	t.Fatalf("expected host-mdns-enabled evidence, got %+v", checks)
}

func TestUpgrade_AllowsSameVersionRefreshForOwnedInstall(t *testing.T) {
	env := setupEnvironment(t, "2.4.0", "v1.30.4+k3s1", "2.4.0", "builder")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
		includeWorkflows: true,
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{}
	orch := newUpgradeOrchestrator(fake, fcli)

	opts := env.options("2.4.0")
	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	updated, _, err := orch.Upgrade(context.Background(), offlineSource, opts)
	if err != nil {
		t.Fatalf("expected same-version refresh to succeed, got: %v", err)
	}
	if updated.InstalledVersion != "2.4.0" {
		t.Fatalf("installed version = %q, want 2.4.0", updated.InstalledVersion)
	}
	if updated.ApplianceProfile != "builder" {
		t.Fatalf("appliance profile = %q, want builder", updated.ApplianceProfile)
	}
	if strings.Contains(strings.Join(fake.calls, " "), "install-binary") {
		t.Fatalf("expected same-version refresh not to replace the k3s binary, got calls %v", fake.calls)
	}
	if !strings.Contains(fcli.lastHelmValues, "applianceProfile: builder") {
		t.Fatalf("prepared values file missing builder profile: %s", fcli.lastHelmValues)
	}

	var importCalls int
	for _, call := range fcli.calls {
		if strings.Contains(call, "image import") {
			importCalls++
		}
	}
	if importCalls != 8 {
		t.Fatalf("expected 8 image import calls during same-version refresh (artifact-server + blob storage + control-plane + UI + host agent + workspace provisioner + workflow controller/executor), got %d: %v", importCalls, fcli.calls)
	}
}

// Unsupported source version must be refused before any mutation.
func TestUpgrade_RefusesUnsupportedSource(t *testing.T) {
	env := setupEnvironment(t, "2.1.0", "v1.29.0+k3s1", "2.1.0", "core")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0", "2.3.1"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{}
	orch := newUpgradeOrchestrator(fake, fcli)

	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	_, _, err := orch.Upgrade(context.Background(), offlineSource, env.options("2.4.0"))
	if err == nil {
		t.Fatal("expected upgrade from an unsupported source to be refused")
	}
	if !strings.Contains(err.Error(), "not a supported upgrade source") {
		t.Errorf("expected a clear refusal message, got: %v", err)
	}
	if len(fake.calls) != 0 {
		t.Errorf("expected no k3s mutation before the compatibility check, got %v", fake.calls)
	}
}

// Failed-upgrade recovery: a chart-apply failure must trigger a
// restore-based rollback that leaves the data directory exactly as it
// was before the upgrade attempt.
func TestUpgrade_FailedChartApplyRollsBackToPreUpgradeBackup(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.4+k3s1", "2.3.0", "core")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{failOn: map[string]bool{"upgrade --install": true}}
	orch := newUpgradeOrchestrator(fake, fcli)

	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	_, checks, err := orch.Upgrade(context.Background(), offlineSource, env.options("2.4.0"))
	if err == nil {
		t.Fatal("expected the simulated chart failure to fail the upgrade")
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("expected the error to mention the rollback, got: %v", err)
	}

	foundRestoreCheck := false
	for _, c := range checks {
		if c.ID == "restore-copy-data" {
			foundRestoreCheck = true
		}
	}
	if !foundRestoreCheck {
		t.Error("expected restore-based rollback evidence checks to be present")
	}

	restoredData, err := os.ReadFile(filepath.Join(env.dataDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if string(restoredData) != "original k3s data" {
		t.Errorf("expected data directory to be restored to its pre-upgrade contents, got: %q", restoredData)
	}

	// installed-state must be untouched: still the source version.
	installed, err := state.Load(env.installedStatePath)
	if err != nil {
		t.Fatal(err)
	}
	if installed.InstalledVersion != "2.3.0" {
		t.Errorf("expected installed-state to remain at the source version after rollback, got %s", installed.InstalledVersion)
	}
}

func TestUpgrade_PreserveFailedStateSkipsRollbackOnChartFailure(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.4+k3s1", "2.3.0", "core")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{failOn: map[string]bool{"upgrade --install": true}}
	orch := newUpgradeOrchestrator(fake, fcli)

	opts := env.options("2.4.0")
	opts.PreserveFailedState = true
	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	_, checks, err := orch.Upgrade(context.Background(), offlineSource, opts)
	if err == nil {
		t.Fatal("expected the simulated chart failure to fail the upgrade")
	}
	if !strings.Contains(err.Error(), "--preserve-failed-state") {
		t.Fatalf("expected error to mention preserved failed state, got: %v", err)
	}
	for _, c := range checks {
		if c.ID == "restore-copy-data" {
			t.Fatal("did not expect restore-based rollback checks when preserving failed state")
		}
	}
	for _, call := range fcli.calls {
		if strings.Contains(call, "image rm") {
			t.Fatalf("expected imported images to remain during preserved failed state, got calls: %v", fcli.calls)
		}
	}
}

func TestUpgrade_RecreatesNamespaceAfterPriorTermination(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.4+k3s1", "2.3.0", "core")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{namespaceTerminating: true}
	orch := newUpgradeOrchestrator(fake, fcli)

	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	if _, _, err := orch.Upgrade(context.Background(), offlineSource, env.options("2.4.0")); err != nil {
		t.Fatalf("expected upgrade to tolerate a terminating namespace and continue, got: %v", err)
	}

	var sawNamespaceCreate bool
	for _, call := range fcli.calls {
		if strings.Contains(call, "create namespace ace-system") {
			sawNamespaceCreate = true
			break
		}
	}
	if !sawNamespaceCreate {
		t.Fatalf("expected namespace recreation after terminating state, got calls: %v", fcli.calls)
	}
}

func TestUpgrade_FailedChartApplyCleansInstallerManagedSecret(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.4+k3s1", "2.3.0", "core")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{failOn: map[string]bool{"upgrade --install": true}}
	orch := newUpgradeOrchestrator(fake, fcli)

	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	if _, _, err := orch.Upgrade(context.Background(), offlineSource, env.options("2.4.0")); err == nil {
		t.Fatal("expected simulated chart failure to fail the upgrade")
	}

	var sawSecretCreate bool
	var sawSecretDelete bool
	for _, call := range fcli.calls {
		if strings.Contains(call, "create secret generic appliance-keys") {
			sawSecretCreate = true
		}
		if strings.Contains(call, "delete secret appliance-keys --ignore-not-found") {
			sawSecretDelete = true
		}
	}
	if !sawSecretCreate {
		t.Fatalf("expected installer-managed secret creation before chart apply, got calls: %v", fcli.calls)
	}
	if !sawSecretDelete {
		t.Fatalf("expected installer-managed secret cleanup on chart failure, got calls: %v", fcli.calls)
	}
}

func TestUpgrade_HTTPSSourcesDoNotCreateSourceCredentialSecrets(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.4+k3s1", "2.3.0", "builder")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
		includeWorkflows: true,
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{}
	orch := newUpgradeOrchestrator(fake, fcli)

	opts := env.options("2.4.0")
	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	if _, _, err := orch.Upgrade(context.Background(), offlineSource, opts); err != nil {
		t.Fatalf("expected upgrade to succeed, got: %v", err)
	}

	for _, call := range fcli.calls {
		if strings.Contains(call, "create secret generic") && (strings.Contains(call, "--from-file=ssh-privatekey=") || strings.Contains(call, "--from-file=known_hosts=")) {
			t.Fatalf("upgrade unexpectedly created SSH source credential secrets: %v", fcli.calls)
		}
	}
}

func TestUpgrade_PreservedIdentityIncludedInTLSSANs(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.0+k3s1", "2.3.0", "core")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{}
	orch := newUpgradeOrchestrator(fake, fcli)

	opts := env.options("2.4.0")
	// Simulate CLI upgrade with omitted identity flags: SANs computed without FQDN.
	opts.ApplianceName = ""
	opts.DNSZone = ""
	opts.TLSSANs = []string{"zonsyssrv1", "192.168.1.101"}
	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	if _, _, err := orch.Upgrade(context.Background(), offlineSource, opts); err != nil {
		t.Fatalf("expected upgrade to succeed, got: %v", err)
	}
	wantFQDN := "testapp.appliance.internal"
	found := false
	for _, san := range fake.lastTLSSANs {
		if san == wantFQDN {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("k3s TLS SANs missing preserved FQDN %q: %#v", wantFQDN, fake.lastTLSSANs)
	}
	if len(fake.lastTLSSANs) == 0 || fake.lastTLSSANs[0] != wantFQDN {
		t.Fatalf("k3s TLS SANs should lead with preserved FQDN: %#v", fake.lastTLSSANs)
	}
}

func TestUpgrade_ArtifactProfileUsesApplianceIdentityForRegistry(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.0+k3s1", "2.3.0", "core")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{}
	orch := newUpgradeOrchestrator(fake, fcli)

	opts := env.options("2.4.0")
	opts.ApplianceProfile = "storage"
	opts.NodeName = "zonsyssrv1"
	opts.ApplianceName = "registry1"
	opts.DNSZone = "appliance.internal"
	opts.TLSSANs = []string{"192.168.1.101"}
	opts.TLSSANs = []string{"zonsyssrv1", "192.168.1.101"}
	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	if _, _, err := orch.Upgrade(context.Background(), offlineSource, opts); err != nil {
		t.Fatalf("expected upgrade to succeed, got: %v", err)
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
}

func TestUpgrade_ArtifactProfileTransitionRemovesWorkflowsRelease(t *testing.T) {
	for _, profile := range []string{"storage", "storage-landns"} {
		t.Run(profile, func(t *testing.T) {
			env := setupEnvironment(t, "2.3.0", "v1.30.0+k3s1", "2.3.0", "builder")
			bundleDir, pub := buildBundle(t, bundleSpec{
				bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
				supportedSources: []string{"2.3.0"},
				includeWorkflows: true,
			})

			fake := &fakeK3s{}
			fcli := &fakeCLI{}
			ownedPaths := map[string][2]int{}
			orch := &upgrade.Orchestrator{
				K3s:        fake.ops(),
				ImagesRun:  fcli.Run,
				HelmRun:    fcli.Run,
				DetectHost: healthyUpgradeHostFacts,
				EnsureOwnedDir: func(path string, uid, gid int, _ os.FileMode) error {
					ownedPaths[path] = [2]int{uid, gid}
					return nil
				},
			}

			opts := env.options("2.4.0")
			opts.ApplianceProfile = profile
			offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
			if _, _, err := orch.Upgrade(context.Background(), offlineSource, opts); err != nil {
				t.Fatalf("expected profile transition upgrade to succeed, got: %v", err)
			}

			var sawWorkflowsUninstall bool
			for _, call := range fcli.calls {
				if strings.Contains(call, "helm --kubeconfig") && strings.Contains(call, "uninstall appliance-workflows") {
					sawWorkflowsUninstall = true
					break
				}
			}
			if !sawWorkflowsUninstall {
				t.Fatalf("expected workflows release removal when switching to %s profile, got calls: %v", profile, fcli.calls)
			}
			wantOwnedPaths := map[string][2]int{
				hostdirs.APIServerLogDir:         {hostdirs.ControlPlaneDirOwnerUID, hostdirs.ApplianceSharedFSGID},
				hostdirs.UILogDir:                {hostdirs.UIDirOwnerUID, hostdirs.ApplianceSharedFSGID},
				hostdirs.HostAgentLogDir:         {hostdirs.HostAgentDirOwnerUID, hostdirs.ApplianceSharedFSGID},
				hostdirs.AutomationRuntimeLogDir: {hostdirs.AutomationRuntimeDirOwnerUID, hostdirs.ApplianceSharedFSGID},
				hostdirs.ArtifactServerLogDir:    {hostdirs.RegistryDirOwnerUID, hostdirs.ApplianceSharedFSGID},
				hostdirs.BlobStorageDir:          {hostdirs.BlobStorageDirOwnerUID, hostdirs.ApplianceSharedFSGID},
				opts.MetadataBundlesDir:          {hostdirs.AutomationRuntimeDirOwnerUID, hostdirs.ApplianceSharedFSGID},
			}
			if profile == "storage-landns" {
				wantOwnedPaths[hostdirs.DNSLogDir] = [2]int{hostdirs.DNSDirOwnerUID, hostdirs.ApplianceSharedFSGID}
			}
			if len(ownedPaths) != len(wantOwnedPaths) {
				t.Fatalf("expected only %s-profile log directory prep %v, got %v", profile, wantOwnedPaths, ownedPaths)
			}
			for path, want := range wantOwnedPaths {
				if got, ok := ownedPaths[path]; !ok || got != want {
					t.Fatalf("expected ownership for %s to be %v, got %v (present=%t)", path, want, got, ok)
				}
			}
			if _, ok := ownedPaths[hostdirs.WorkflowControllerLogDir]; ok {
				t.Fatalf("%s upgrade must not prepare %s: %v", profile, hostdirs.WorkflowControllerLogDir, ownedPaths)
			}
		})
	}
}

func TestUpgrade_RefusesArtifactCapabilityRemoval(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.0+k3s1", "2.3.0", "storage")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{}
	orch := newUpgradeOrchestrator(fake, fcli)

	opts := env.options("2.4.0")
	opts.ApplianceProfile = "core"
	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	_, _, err := orch.Upgrade(context.Background(), offlineSource, opts)
	if err == nil {
		t.Fatal("expected artifact capability removal to be refused")
	}
	if !strings.Contains(err.Error(), "not supported in place") {
		t.Fatalf("expected clear refusal, got: %v", err)
	}
	if len(fake.calls) != 0 || len(fcli.calls) != 0 {
		t.Fatalf("expected no mutations before refusal, got k3s=%v cli=%v", fake.calls, fcli.calls)
	}
}

func TestUpgrade_RefusesDNSCapabilityRemoval(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.0+k3s1", "2.3.0", "landns")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{}
	orch := newUpgradeOrchestrator(fake, fcli)

	opts := env.options("2.4.0")
	opts.ApplianceProfile = "core"
	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	_, _, err := orch.Upgrade(context.Background(), offlineSource, opts)
	if err == nil {
		t.Fatal("expected dns capability removal to be refused")
	}
	if !strings.Contains(err.Error(), "not supported in place") || !strings.Contains(err.Error(), "dns-capable") {
		t.Fatalf("expected clear dns refusal, got: %v", err)
	}
	if len(fake.calls) != 0 || len(fcli.calls) != 0 {
		t.Fatalf("expected no mutations before refusal, got k3s=%v cli=%v", fake.calls, fcli.calls)
	}
}

func TestUpgrade_RegistryFailureAfterArtifactEnablementUninstallsFreshRelease(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.0+k3s1", "2.3.0", "core")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{failOn: map[string]bool{"upgrade --install appliance-registry": true}}
	orch := newUpgradeOrchestrator(fake, fcli)

	opts := env.options("2.4.0")
	opts.ApplianceProfile = "storage"
	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	if _, checks, err := orch.Upgrade(context.Background(), offlineSource, opts); err == nil {
		t.Fatal("expected simulated registry failure to abort upgrade")
	} else if len(checks) == 0 {
		t.Fatal("expected diagnostics checks on failure")
	}

	var sawUninstall, sawRollback, sawLogs bool
	for _, call := range fcli.calls {
		sawUninstall = sawUninstall || strings.Contains(call, "helm --kubeconfig") && strings.Contains(call, "uninstall appliance-registry")
		sawRollback = sawRollback || strings.Contains(call, "helm --kubeconfig") && strings.Contains(call, "rollback appliance-registry")
		sawLogs = sawLogs || strings.Contains(call, "logs --all-containers=true --tail=200 -l app.kubernetes.io/instance=appliance-registry")
	}
	if !sawUninstall || sawRollback {
		t.Fatalf("expected fresh registry release uninstall instead of rollback, got calls: %v", fcli.calls)
	}
	if !sawLogs {
		t.Fatalf("expected registry diagnostics logs capture, got calls: %v", fcli.calls)
	}
}

func TestUpgrade_CoreProfilePreparesWorkflowServiceLogDirectories(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.0+k3s1", "2.3.0", "core")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{}
	ownedPaths := map[string][2]int{}
	orch := &upgrade.Orchestrator{
		K3s:        fake.ops(),
		ImagesRun:  fcli.Run,
		HelmRun:    fcli.Run,
		DetectHost: healthyUpgradeHostFacts,
		EnsureOwnedDir: func(path string, uid, gid int, _ os.FileMode) error {
			ownedPaths[path] = [2]int{uid, gid}
			return nil
		},
	}

	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	opts := env.options("2.4.0")
	if _, _, err := orch.Upgrade(context.Background(), offlineSource, opts); err != nil {
		t.Fatalf("expected core-profile upgrade to succeed, got: %v", err)
	}

	wantOwnedPaths := map[string][2]int{
		hostdirs.APIServerLogDir:         {hostdirs.ControlPlaneDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		hostdirs.UILogDir:                {hostdirs.UIDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		hostdirs.AutomationRuntimeLogDir: {hostdirs.AutomationRuntimeDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		hostdirs.BlobStorageDir:          {hostdirs.BlobStorageDirOwnerUID, hostdirs.ApplianceSharedFSGID},
		opts.MetadataBundlesDir:          {hostdirs.AutomationRuntimeDirOwnerUID, hostdirs.ApplianceSharedFSGID},
	}
	if len(ownedPaths) != len(wantOwnedPaths) {
		t.Fatalf("expected only core-profile log directory prep %v, got %v", wantOwnedPaths, ownedPaths)
	}
	for path, want := range wantOwnedPaths {
		if got, ok := ownedPaths[path]; !ok || got != want {
			t.Fatalf("expected ownership for %s to be %v, got %v (present=%t)", path, want, got, ok)
		}
	}
	if _, ok := ownedPaths[hostdirs.ArtifactServerLogDir]; ok {
		t.Fatalf("core upgrade must not prepare %s: %v", hostdirs.ArtifactServerLogDir, ownedPaths)
	}
}

// fakeCLI simulates ctr/helm/kubectl for the images and helm adapters.
type fakeCLI struct {
	failOn               map[string]bool
	calls                []string
	missingNamespace     bool
	namespaceTerminating bool
	namespacePolls       int
	secrets              map[string]bool
	lastHelmValues       string
	helmValues           map[string]string
	importedImages       []string
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
	switch {
	case name == "ssh-keygen" && contains(args, "-y"):
		return "ssh-ed25519 AAAATEST generated@test\n", nil
	case name == "ssh-keygen":
		var keyPath string
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "-f" {
				keyPath = args[i+1]
				break
			}
		}
		if keyPath != "" {
			if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
				return "", err
			}
			if err := os.WriteFile(keyPath, []byte("private-key\n"), 0o600); err != nil {
				return "", err
			}
			if err := os.WriteFile(keyPath+".pub", []byte("ssh-ed25519 AAAATEST generated@test\n"), 0o644); err != nil {
				return "", err
			}
		}
		return "", nil
	case name == "ssh-keyscan":
		host := ""
		if len(args) > 0 {
			host = args[len(args)-1]
		}
		if host == "" {
			host = "git.internal.example.com"
		}
		return host + " ssh-ed25519 AAAAHOSTKEY generated-host\n", nil
	case name == "ctr" && contains(args, "ls"):
		return strings.Join(f.importedImages, "\n"), nil
	case name == "ctr" && contains(args, "import"):
		for _, ref := range upgradeTestImageRefsForArchive(importPathArg(args)) {
			f.addImportedImage(ref)
		}
		return "", nil
	case name == "kubectl" && contains(args, "get") && contains(args, "namespace"):
		if f.namespaceTerminating {
			f.namespacePolls++
			if f.namespacePolls < 2 {
				return "Terminating", nil
			}
			f.namespaceTerminating = false
			f.missingNamespace = true
			return "", fmt.Errorf("simulated namespace not found after terminating")
		}
		if f.missingNamespace {
			return "", fmt.Errorf("simulated namespace not found")
		}
		return "Active", nil
	case name == "kubectl" && contains(args, "create") && contains(args, "namespace"):
		f.missingNamespace = false
		return "", nil
	case name == "kubectl" && contains(args, "get") && contains(args, "secret") && contains(args, "json"):
		secretName := ""
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "secret" {
				secretName = args[i+1]
				break
			}
		}
		if secretName == "appliance-keys" {
			seedFile := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize))
			payload, _ := json.Marshal(map[string]any{
				"data": map[string]string{
					"session_ed25519_private.key":  base64.StdEncoding.EncodeToString([]byte(seedFile)),
					"registry_ed25519_private.key": base64.StdEncoding.EncodeToString([]byte(seedFile)),
					"api_token_pepper.key":         base64.StdEncoding.EncodeToString([]byte("api-pepper")),
					"refresh_pepper.key":           base64.StdEncoding.EncodeToString([]byte("refresh-pepper")),
					"cursor_hmac.key":              base64.StdEncoding.EncodeToString([]byte("cursor-hmac")),
				},
			})
			return string(payload), nil
		}
		return "", fmt.Errorf("simulated secret not found")
	case name == "kubectl" && contains(args, "get") && contains(args, "secret") && strings.Contains(call, "registry_ed25519_private.key"):
		seedFile := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize))
		return base64.StdEncoding.EncodeToString([]byte(seedFile)), nil
	case name == "kubectl" && contains(args, "get") && contains(args, "secret"):
		if f.secrets == nil {
			f.secrets = map[string]bool{}
		}
		if f.secrets[args[len(args)-1]] {
			return "", nil
		}
		return "", fmt.Errorf("simulated secret not found")
	case name == "kubectl" && contains(args, "create") && contains(args, "secret"):
		if f.secrets == nil {
			f.secrets = map[string]bool{}
		}
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "generic" {
				f.secrets[args[i+1]] = true
				return "", nil
			}
		}
		return "", nil
	case name == "kubectl" && contains(args, "delete") && contains(args, "secret"):
		if f.secrets == nil {
			f.secrets = map[string]bool{}
		}
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "secret" {
				delete(f.secrets, args[i+1])
				break
			}
		}
		return "", nil
	case name == "kubectl" && contains(args, "get") && contains(args, "nodes"):
		return "appliance-node   Ready   control-plane   1m   v1.30.4+k3s1\n", nil
	case name == "kubectl" && contains(args, "get") && contains(args, "storageclass"):
		return "storageclass.storage.k8s.io/local-path", nil
	case name == "kubectl" && contains(args, "get") && contains(args, "deployment"):
		// availableReplicas polls: coredns, local-path-provisioner, dns-server, …
		return "1", nil
	case name == "kubectl" && contains(args, "get") && contains(args, "svc") && contains(args, "traefik"):
		return `{"spec":{"externalIPs":["10.42.0.1"]}}`, nil
	case name == "kubectl" && contains(args, "patch") && contains(args, "svc") && contains(args, "traefik"):
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

func upgradeTestImageRefsForArchive(path string) []string {
	switch filepath.Base(path) {
	case "control-plane.tar":
		return []string{"internal/control-plane:2.4.0"}
	case "appliance-ui.tar":
		return []string{"internal/appliance-ui:2.4.0"}
	case "appliance-host-agent.tar":
		return []string{"registry.local/appliance-host-agent@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}
	case "blob-storage.tar":
		return []string{"registry.local/blob-storage@sha256:abababababababababababababababababababababababababababababababab"}
	case "workspace-provisioner.tar":
		return []string{"registry.local/workspace-provisioner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	case "artifact-server.tar":
		return []string{"registry.local/artifact-server@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	case "dns-server.tar":
		return []string{"registry.local/coredns@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
	case "inference-runtime.tar":
		return []string{"registry.local/inference-runtime@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}
	case "workflow-controller.tar":
		return []string{"quay.io/argoproj/workflow-controller:v3.5.10"}
	case "workflow-executor.tar":
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

func helmReleaseNameFromCall(call string) string {
	fields := strings.Fields(call)
	for i := 0; i < len(fields)-2; i++ {
		if fields[i] == "upgrade" && fields[i+1] == "--install" {
			return fields[i+2]
		}
	}
	return ""
}
