package upgrade_test

import (
	"context"
	"crypto/ed25519"
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
	argoVersion      string
	chartVersion     string
	supportedSources []string
}

func buildBundle(t *testing.T, spec bundleSpec) (dir string, pub verify.PublicKey) {
	t.Helper()
	dir = t.TempDir()

	entries := []struct {
		relPath   string
		component string
		content   string
	}{
		{"k3s/binary/k3s", "k3s-binary", "fake k3s binary " + spec.k3sVersion},
		{"charts/appliance-chart.tgz", "chart", "fake chart " + spec.chartVersion},
		{"crds/argo-crds.yaml", "crds", "fake crds " + spec.argoVersion},
		{"configuration/values.yaml", "configuration", "replicaCount: 1\n"},
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
	}

	doc := map[string]any{
		"schemaVersion": 1,
		"bundleVersion": spec.bundleVersion,
		"releaseId":     "01J8QK3F9G7XA6P0V6ZC9N6R4T",
		"hostBaseline":  map[string]any{"os": "ubuntu", "osVersion": "24.04", "arch": "amd64"},
		"builtAt":       "2026-07-04T00:00:00Z",
		"compatibility": map[string]any{
			"k3sVersion": spec.k3sVersion, "chartVersion": spec.chartVersion, "argoVersion": spec.argoVersion,
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

func setupEnvironment(t *testing.T, installedVersion, k3sVersion, argoVersion, chartVersion string) environment {
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
		Components:          state.Components{K3sVersion: k3sVersion, ChartVersion: chartVersion, ArgoVersion: argoVersion},
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
		ChartReleaseName:       "appliance",
		ChartNamespace:         "appliance",
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
			env := setupEnvironment(t, source, "v1.30.0+k3s1", "3.5.1", "2.3.0")
			bundleDir, pub := buildBundle(t, bundleSpec{
				bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", argoVersion: "3.5.2", chartVersion: "2.4.0",
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

// Unsupported source version must be refused before any mutation.
func TestUpgrade_RefusesUnsupportedSource(t *testing.T) {
	env := setupEnvironment(t, "2.1.0", "v1.29.0+k3s1", "3.4.0", "2.1.0")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", argoVersion: "3.5.2", chartVersion: "2.4.0",
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

// Argo CRD downgrade must be refused.
func TestUpgrade_RefusesArgoCRDDowngrade(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.0+k3s1", "3.5.5", "2.3.0")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", argoVersion: "3.5.1", chartVersion: "2.4.0",
		supportedSources: []string{"2.3.0"},
	})

	fake := &fakeK3s{}
	fcli := &fakeCLI{}
	orch := &upgrade.Orchestrator{K3s: fake.ops(), ImagesRun: fcli.Run, HelmRun: fcli.Run}

	offlineSource := install.OfflineSource{BundleDir: bundleDir, PublicKey: &pub}
	_, _, err := orch.Upgrade(context.Background(), offlineSource, env.options("2.4.0"))
	if err == nil {
		t.Fatal("expected a CRD downgrade to be refused")
	}
	if !strings.Contains(err.Error(), "downgrade") {
		t.Errorf("expected a downgrade-specific message, got: %v", err)
	}
}

// Failed-upgrade recovery: a chart-apply failure must trigger a
// restore-based rollback that leaves the data directory exactly as it
// was before the upgrade attempt.
func TestUpgrade_FailedChartApplyRollsBackToPreUpgradeBackup(t *testing.T) {
	env := setupEnvironment(t, "2.3.0", "v1.30.4+k3s1", "3.5.1", "2.3.0")
	bundleDir, pub := buildBundle(t, bundleSpec{
		bundleVersion: "2.4.0", k3sVersion: "v1.30.4+k3s1", argoVersion: "3.5.2", chartVersion: "2.4.0",
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

// fakeCLI simulates ctr/helm/kubectl for the images and helm adapters.
type fakeCLI struct {
	failOn map[string]bool
	calls  []string
}

func (f *fakeCLI) Run(_ context.Context, name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	for substr, fail := range f.failOn {
		if fail && strings.Contains(call, substr) {
			return "", fmt.Errorf("simulated failure for %q", substr)
		}
	}
	return "", nil
}
