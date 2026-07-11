package install_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/install"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

func TestOfflineSource_PrefersValuesYAMLWhenMultipleConfigurationEntriesExist(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"bin/zonctl-real":                         "fake zonctl binary",
		"k3s/binary/k3s":                          "fake k3s binary",
		"charts/appliance-chart-2.4.0.tgz":        "fake chart",
		"configuration/configuration.schema.json": `{"type":"object"}`,
		"configuration/values.yaml":               "replicaCount: 1\n",
	}

	var manifestEntries []map[string]any
	for rel, content := range files {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
		digest, err := verify.Digest(full)
		if err != nil {
			t.Fatal(err)
		}
		component := "configuration"
		switch {
		case rel == "bin/zonctl-real":
			component = "appliance"
		case rel == "k3s/binary/k3s":
			component = "k3s-binary"
		case rel == "charts/appliance-chart-2.4.0.tgz":
			component = "chart"
		}
		manifestEntries = append(manifestEntries, map[string]any{
			"path": rel, "component": component, "digest": digest, "sizeBytes": len(content),
		})
	}

	doc := map[string]any{
		"schemaVersion": 1,
		"bundleVersion": "2.4.0",
		"releaseId":     "release-2.4.0",
		"hostBaseline":  map[string]any{"os": "ubuntu", "osVersion": "24.04", "arch": "amd64"},
		"builtAt":       "2026-07-06T00:00:00Z",
		"compatibility": map[string]any{"k3sVersion": "v1.30.4+k3s1", "chartVersion": "2.4.0"},
		"signingKeyId":  "release-signing-key",
		"entries":       manifestEntries,
	}
	manifestBytes, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "release-manifest.json"), manifestBytes, 0o640); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := verify.Sign(priv, manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "release-manifest.sig"), sig, 0o640); err != nil {
		t.Fatal(err)
	}

	source := install.OfflineSource{
		BundleDir: dir,
		PublicKey: &verify.PublicKey{ID: "release-signing-key", Key: pub},
	}
	resolved, _, err := source.Resolve(context.Background())
	if err != nil {
		t.Fatalf("expected bundle to resolve, got: %v", err)
	}
	if resolved.BundleVersion != "2.4.0" {
		t.Fatalf("expected bundle version 2.4.0, got %s", resolved.BundleVersion)
	}
	if filepath.Base(resolved.ZonctlBinaryPath) != "zonctl-real" {
		t.Fatalf("expected zonctl-real to be selected, got %s", resolved.ZonctlBinaryPath)
	}
	if filepath.Base(resolved.ConfigurationPath) != "values.yaml" {
		t.Fatalf("expected values.yaml to be selected, got %s", resolved.ConfigurationPath)
	}
}

func TestOfflineSource_SelectsPrimaryChartAndOptionalArgoArtifacts(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"bin/zonctl-real": "fake zonctl binary",
		"k3s/binary/k3s":  "fake k3s binary",
		"charts/appliance-argo-workflows-chart-3.5.10.tgz": "fake argo chart",
		"charts/appliance-chart-2.4.0.tgz":                 "fake appliance chart",
		"configuration/values.yaml":                        "replicaCount: 1\n",
		"kubernetes/crds/workflows.argoproj.io.yaml":       "kind: CustomResourceDefinition\n",
	}

	var manifestEntries []map[string]any
	for rel, content := range files {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
		digest, err := verify.Digest(full)
		if err != nil {
			t.Fatal(err)
		}
		component := "configuration"
		switch {
		case rel == "bin/zonctl-real":
			component = "appliance"
		case rel == "k3s/binary/k3s":
			component = "k3s-binary"
		case filepath.Dir(rel) == "charts":
			component = "chart"
		case filepath.Dir(rel) == "kubernetes/crds":
			component = "kubernetes-crds"
		}
		manifestEntries = append(manifestEntries, map[string]any{
			"path": rel, "component": component, "digest": digest, "sizeBytes": len(content),
		})
	}

	doc := map[string]any{
		"schemaVersion": 1,
		"bundleVersion": "2.4.0",
		"releaseId":     "release-2.4.0",
		"hostBaseline":  map[string]any{"os": "ubuntu", "osVersion": "24.04", "arch": "amd64"},
		"builtAt":       "2026-07-06T00:00:00Z",
		"compatibility": map[string]any{"k3sVersion": "v1.30.4+k3s1", "chartVersion": "2.4.0", "argoVersion": "3.5.10"},
		"signingKeyId":  "release-signing-key",
		"entries":       manifestEntries,
	}
	manifestBytes, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "release-manifest.json"), manifestBytes, 0o640); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := verify.Sign(priv, manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "release-manifest.sig"), sig, 0o640); err != nil {
		t.Fatal(err)
	}

	source := install.OfflineSource{
		BundleDir: dir,
		PublicKey: &verify.PublicKey{ID: "release-signing-key", Key: pub},
	}
	resolved, _, err := source.Resolve(context.Background())
	if err != nil {
		t.Fatalf("expected bundle to resolve, got: %v", err)
	}
	if filepath.Base(resolved.ChartPath) != "appliance-chart-2.4.0.tgz" {
		t.Fatalf("expected appliance chart to be selected, got %s", resolved.ChartPath)
	}
	if filepath.Base(resolved.ArgoChartPath) != "appliance-argo-workflows-chart-3.5.10.tgz" {
		t.Fatalf("expected argo chart to be selected, got %s", resolved.ArgoChartPath)
	}
	if len(resolved.ArgoCRDPaths) != 1 || filepath.Base(resolved.ArgoCRDPaths[0]) != "workflows.argoproj.io.yaml" {
		t.Fatalf("expected one argo CRD path, got %+v", resolved.ArgoCRDPaths)
	}
}
