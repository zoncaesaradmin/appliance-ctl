package releasebundle_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/releasebundle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/releaseinput"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

func writeTestFile(t *testing.T, root, rel, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func buildReleaseInputDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"control-plane.oci.tar.zst":            "control-plane",
		"appliance-chart-2.4.0.tgz":            "chart",
		"argo-crds-3.5.2.tar.zst":              "crds-compressed",
		"configuration.schema.json":            `{"type":"object"}`,
		"compatibility.json":                   `{"k3sVersion":"v1.30.4+k3s1"}`,
		"checksums.txt":                        "checksums",
		"sbom/appliance.spdx.json":             "{}",
		"provenance/appliance.provenance.json": "{}",
		"notices/THIRD-PARTY-NOTICES.txt":      "notice",
		"tests/conformance.tar.zst":            "tests",
	}
	for rel, content := range files {
		writeTestFile(t, root, rel, content, 0o640)
	}

	digestOf := func(rel string) string {
		digest, err := verify.Digest(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		return digest
	}
	dirDigestOf := func(rel string) string {
		digest, err := releaseinput.DirectoryManifestDigest(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		return digest
	}

	doc := map[string]any{
		"schemaVersion":  1,
		"productVersion": "2.4.0",
		"releaseId":      "release-2.4.0",
		"generatedAt":    "2026-07-06T00:00:00Z",
		"artifacts": map[string]any{
			"controlPlaneImage":   map[string]any{"path": "control-plane.oci.tar.zst", "digest": digestOf("control-plane.oci.tar.zst"), "sizeBytes": len("control-plane")},
			"applianceChart":      map[string]any{"path": "appliance-chart-2.4.0.tgz", "digest": digestOf("appliance-chart-2.4.0.tgz"), "sizeBytes": len("chart")},
			"argoCrds":            map[string]any{"path": "argo-crds-3.5.2.tar.zst", "digest": digestOf("argo-crds-3.5.2.tar.zst"), "sizeBytes": len("crds-compressed")},
			"configurationSchema": map[string]any{"path": "configuration.schema.json", "digest": digestOf("configuration.schema.json"), "sizeBytes": len(`{"type":"object"}`)},
			"compatibility":       map[string]any{"path": "compatibility.json", "digest": digestOf("compatibility.json"), "sizeBytes": len(`{"k3sVersion":"v1.30.4+k3s1"}`)},
			"checksums":           map[string]any{"path": "checksums.txt", "digest": digestOf("checksums.txt"), "sizeBytes": len("checksums")},
			"sbom":                map[string]any{"path": "sbom", "manifestDigest": dirDigestOf("sbom")},
			"provenance":          map[string]any{"path": "provenance", "manifestDigest": dirDigestOf("provenance")},
			"notices":             map[string]any{"path": "notices", "manifestDigest": dirDigestOf("notices")},
			"tests":               map[string]any{"path": "tests", "manifestDigest": dirDigestOf("tests")},
		},
		"compatibility": map[string]any{
			"k3sVersion":              "v1.30.4+k3s1",
			"chartVersion":            "2.4.0",
			"argoVersion":             "3.5.2",
			"supportedUpgradeSources": []string{"2.3.0"},
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "release-input.json"), data, 0o640); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestAssembleAndVerifyBundle(t *testing.T) {
	releaseInputDir := buildReleaseInputDir(t)
	staging := t.TempDir()
	writeTestFile(t, staging, "zonctl", "zonctl-binary", 0o750)
	writeTestFile(t, staging, "k3s", "k3s-binary", 0o750)
	writeTestFile(t, staging, "install.sh", "#!/bin/sh\n", 0o750)
	writeTestFile(t, staging, "k3s-airgap-images.tar", "k3s images", 0o640)
	writeTestFile(t, staging, "control-plane.tar", "app image", 0o640)
	writeTestFile(t, staging, "chart.tgz", "chart", 0o640)
	writeTestFile(t, staging, "crds.yaml", "kind: CustomResourceDefinition\n", 0o640)
	writeTestFile(t, staging, "values.yaml", "replicaCount: 1\n", 0o640)

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPath := filepath.Join(staging, "release-signing.key")
	if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := releasebundle.Config{
		SchemaVersion:         1,
		ReleaseInputDir:       releaseInputDir,
		BundleDir:             filepath.Join(t.TempDir(), "bundle"),
		SigningKeyID:          "release-signing-key",
		SigningPrivateKeyPath: privateKeyPath,
		HostBaseline:          releasebundle.HostBaseline{OS: "ubuntu", OSVersion: "24.04", Arch: "amd64"},
		Entries: []releasebundle.EntryConfig{
			{SourcePath: filepath.Join(staging, "zonctl"), TargetPath: "zonctl", Component: "appliance", Executable: true},
			{SourcePath: filepath.Join(staging, "k3s"), TargetPath: "k3s/binary/k3s", Component: "k3s-binary", Executable: true},
			{SourcePath: filepath.Join(staging, "install.sh"), TargetPath: "k3s/install/install.sh", Component: "k3s-install", Executable: true},
			{SourcePath: filepath.Join(staging, "k3s-airgap-images.tar"), TargetPath: "k3s/images/k3s-airgap-images.tar", Component: "k3s-images"},
			{SourcePath: filepath.Join(staging, "control-plane.tar"), TargetPath: "oci-images/control-plane.tar", Component: "oci-images", ImageReference: "internal/control-plane:2.4.0"},
			{SourcePath: filepath.Join(staging, "chart.tgz"), TargetPath: "charts/appliance-chart-2.4.0.tgz", Component: "chart"},
			{SourcePath: filepath.Join(staging, "crds.yaml"), TargetPath: "crds/argo-crds.yaml", Component: "crds"},
			{SourcePath: filepath.Join(staging, "values.yaml"), TargetPath: "configuration/values.yaml", Component: "configuration"},
		},
	}

	result, err := releasebundle.Assemble(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected bundle assembly to succeed, got: %v", err)
	}
	if result.EntryCount == 0 {
		t.Fatal("expected non-empty bundle")
	}

	b, err := releasebundle.VerifyBundle(result.BundleDir, result.PublicKeyPath)
	if err != nil {
		t.Fatalf("expected assembled bundle to verify, got: %v", err)
	}
	if b.BundleVersion != "2.4.0" || b.ReleaseID != "release-2.4.0" {
		t.Fatalf("unexpected bundle metadata: %+v", b)
	}
	if _, err := os.Stat(filepath.Join(result.BundleDir, "configuration", "configuration.schema.json")); err != nil {
		t.Fatalf("expected configuration schema to be carried into the bundle: %v", err)
	}
}

func TestAssembleAndVerifyBundleWithoutSupportedUpgradeSources(t *testing.T) {
	releaseInputDir := buildReleaseInputDir(t)

	manifestPath := filepath.Join(releaseInputDir, "release-input.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	compatibility, ok := doc["compatibility"].(map[string]any)
	if !ok {
		t.Fatal("expected compatibility object")
	}
	delete(compatibility, "supportedUpgradeSources")
	updated, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, updated, 0o640); err != nil {
		t.Fatal(err)
	}

	staging := t.TempDir()
	writeTestFile(t, staging, "zonctl", "zonctl-binary", 0o750)
	writeTestFile(t, staging, "k3s", "k3s-binary", 0o750)
	writeTestFile(t, staging, "install.sh", "#!/bin/sh\n", 0o750)
	writeTestFile(t, staging, "k3s-airgap-images.tar", "k3s images", 0o640)
	writeTestFile(t, staging, "control-plane.tar", "app image", 0o640)
	writeTestFile(t, staging, "chart.tgz", "chart", 0o640)
	writeTestFile(t, staging, "crds.yaml", "kind: CustomResourceDefinition\n", 0o640)
	writeTestFile(t, staging, "values.yaml", "replicaCount: 1\n", 0o640)

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPath := filepath.Join(staging, "release-signing.key")
	if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := releasebundle.Config{
		SchemaVersion:         1,
		ReleaseInputDir:       releaseInputDir,
		BundleDir:             filepath.Join(t.TempDir(), "bundle"),
		SigningKeyID:          "release-signing-key",
		SigningPrivateKeyPath: privateKeyPath,
		HostBaseline:          releasebundle.HostBaseline{OS: "ubuntu", OSVersion: "24.04", Arch: "amd64"},
		Entries: []releasebundle.EntryConfig{
			{SourcePath: filepath.Join(staging, "zonctl"), TargetPath: "zonctl", Component: "appliance", Executable: true},
			{SourcePath: filepath.Join(staging, "k3s"), TargetPath: "k3s/binary/k3s", Component: "k3s-binary", Executable: true},
			{SourcePath: filepath.Join(staging, "install.sh"), TargetPath: "k3s/install/install.sh", Component: "k3s-install", Executable: true},
			{SourcePath: filepath.Join(staging, "k3s-airgap-images.tar"), TargetPath: "k3s/images/k3s-airgap-images.tar", Component: "k3s-images"},
			{SourcePath: filepath.Join(staging, "control-plane.tar"), TargetPath: "oci-images/control-plane.tar", Component: "oci-images", ImageReference: "internal/control-plane:2.4.0"},
			{SourcePath: filepath.Join(staging, "chart.tgz"), TargetPath: "charts/appliance-chart-2.4.0.tgz", Component: "chart"},
			{SourcePath: filepath.Join(staging, "crds.yaml"), TargetPath: "crds/argo-crds.yaml", Component: "crds"},
			{SourcePath: filepath.Join(staging, "values.yaml"), TargetPath: "configuration/values.yaml", Component: "configuration"},
		},
	}

	result, err := releasebundle.Assemble(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected bundle assembly to succeed, got: %v", err)
	}

	if _, err := releasebundle.VerifyBundle(result.BundleDir, result.PublicKeyPath); err != nil {
		t.Fatalf("expected assembled bundle to verify, got: %v", err)
	}
}
