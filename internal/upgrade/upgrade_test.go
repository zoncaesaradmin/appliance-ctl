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

	"github.com/zoncaesaradmin/appliance-ctl/internal/install"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
	"github.com/zoncaesaradmin/appliance-ctl/internal/upgrade"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

type bundleSpec struct {
	bundleVersion    string
	k3sVersion       string
	chartVersion     string
	supportedSources []string
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
		{"k3s/binary/k3s", "k3s-binary", "fake k3s binary " + spec.k3sVersion, ""},
		{"charts/appliance-chart.tgz", "chart", "fake chart " + spec.chartVersion, ""},
		{"charts/appliance-registry-2.1.7.tgz", "chart", "fake registry chart", ""},
		{"configuration/values.yaml", "configuration", "replicaCount: 1\nsecrets:\n  keysSecretName: appliance-keys\n", ""},
		{"oci-images/control-plane.tar", "oci-images", "fake control-plane image " + spec.bundleVersion, "internal/control-plane:" + spec.bundleVersion},
		{"oci-images/appliance-ui.tar", "oci-images", "fake appliance UI image " + spec.bundleVersion, "internal/appliance-ui:" + spec.bundleVersion},
		{"oci-images/workspace-provisioner.tar", "oci-images", "fake workspace provisioner image " + spec.bundleVersion, "registry.local/workspace-provisioner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"oci-images/automation-dev.tar", "oci-images", "fake automation-dev builder image " + spec.bundleVersion, "registry.local/automation-dev@sha256:5ccdfda08e940614d030e377b75f048a55e3f61cbb0234294ad333f27afe222c"},
		{"oci-images/zot.tar", "oci-images", "fake zot image " + spec.bundleVersion, "registry.local/zot@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
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
		manifestEntries = append(manifestEntries, map[string]any{
			"path": e.relPath, "component": e.component, "digest": digest, "sizeBytes": len(e.content),
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
			"zotVersion":              "2.1.7",
			"supportedUpgradeSources": spec.supportedSources,
		},
		"signingKeyId": "release-signing-key",
		"entries":      manifestEntries,
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
	failStep string
	calls    []string
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
			if f.failStep == "write-config" {
				return fmt.Errorf("simulated write-config failure")
			}
			return os.WriteFile(path, []byte(cfg.Render()), 0o640)
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
		TargetApplianceVersion: targetVersion,
		InstalledStatePath:     env.installedStatePath,
		K3sConfigPath:          env.k3sConfigPath,
		K3sUnitPath:            env.k3sUnitPath,
		K3sBinaryDestPath:      env.k3sBinaryDestPath,
		K3sUnitName:            "k3s.service",
		K3sDataDir:             env.dataDir,
		KubeconfigPath:         env.kubeconfigPath,
		NodeName:               "appliance-node",
		ZonctlRealDestPath:     filepath.Join(env.stateDir, "usr-local-lib", "zon", "bin", "zonctl-real"),
		ZonctlLauncherDestPath: filepath.Join(env.stateDir, "usr-local-bin", "zonctl"),
		ChartReleaseName:       "appliance",
		ChartNamespace:         "appliance-system",
		BackupRoot:             env.backupRoot,
		TransactionID:          "txn-upgrade-test",
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
			orch := &upgrade.Orchestrator{K3s: fake.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run}

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
	orch := &upgrade.Orchestrator{K3s: fake.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run}

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

func TestUpgrade_PreservesInstalledApplianceProfileWhenFlagOmitted(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.0+k3s1", "2.3.0", "storage")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{}
	orch := &upgrade.Orchestrator{K3s: fake.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run}

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

func TestUpgrade_AllowsSameVersionRefreshForOwnedInstall(t *testing.T) {
	env := setupEnvironment(t, "2.4.0", "v1.30.4+k3s1", "2.4.0", "builder")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{}
	orch := &upgrade.Orchestrator{K3s: fake.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run}

	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	updated, _, err := orch.Upgrade(context.Background(), offlineSource, env.options("2.4.0"))
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
	if importCalls != 5 {
		t.Fatalf("expected 5 image import calls during same-version refresh (zot + control-plane + UI + workspace provisioner + automation-dev), got %d: %v", importCalls, fcli.calls)
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
	orch := &upgrade.Orchestrator{K3s: fake.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run}

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
	orch := &upgrade.Orchestrator{K3s: fake.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run}

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
	orch := &upgrade.Orchestrator{K3s: fake.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run}

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
	orch := &upgrade.Orchestrator{K3s: fake.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run}

	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	if _, _, err := orch.Upgrade(context.Background(), offlineSource, env.options("2.4.0")); err != nil {
		t.Fatalf("expected upgrade to tolerate a terminating namespace and continue, got: %v", err)
	}

	var sawNamespaceCreate bool
	for _, call := range fcli.calls {
		if strings.Contains(call, "create namespace appliance") {
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
	orch := &upgrade.Orchestrator{K3s: fake.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run}

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
	})
	buildCatalogPath := filepath.Join(env.stateDir, "build-catalog.yaml")
	if err := os.WriteFile(buildCatalogPath, []byte("workProfiles:\n  - name: platform-dev\n    repos:\n      - name: app\nrepos:\n  - name: app\n    url: https://git.internal.example.com/team/app.git\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	fake := &fakeK3s{}
	fcli := &fakeCLI{}
	orch := &upgrade.Orchestrator{K3s: fake.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run}

	opts := env.options("2.4.0")
	opts.BuildCatalogPath = buildCatalogPath
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

// fakeCLI simulates ctr/helm/kubectl for the images and helm adapters.
type fakeCLI struct {
	failOn               map[string]bool
	calls                []string
	missingNamespace     bool
	namespaceTerminating bool
	namespacePolls       int
	secrets              map[string]bool
	lastHelmValues       string
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
	case name == "kubectl" && contains(args, "get") && contains(args, "deployment") && contains(args, "coredns"):
		return "1", nil
	case name == "kubectl" && contains(args, "get") && contains(args, "deployment") && contains(args, "local-path-provisioner"):
		return "1", nil
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
	case "workspace-provisioner.tar":
		return []string{"registry.local/workspace-provisioner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	case "automation-dev.tar":
		return []string{"registry.local/automation-dev@sha256:5ccdfda08e940614d030e377b75f048a55e3f61cbb0234294ad333f27afe222c"}
	case "zot.tar":
		return []string{"registry.local/zot@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
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
