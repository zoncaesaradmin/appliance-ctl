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
		"control-plane.oci.tar.zst":                         "control-plane",
		"appliance-ui.oci.tar.zst":                          "ui-image",
		"appliance-host-agent.oci.tar.zst":                  "host-agent-image",
		"appliance-host-agentd":                             "host-agentd",
		"host-packages/ubuntu/24.04/amd64/avahi-daemon.deb": "avahi-deb",
		"appliance-chart-2.4.0.tgz":                         "chart",
		"artifact-server.oci.tar.zst":                       "artifact-server-image",
		"appliance-registry-2.1.7.tgz":                      "artifact-server-chart",
		"coredns.oci.tar.zst":                               "dns-image",
		"appliance-dns-1.14.4.tgz":                          "dns-chart",
		"blob-storage.oci.tar.zst":                          "blob-storage-image",
		"inference-runtime.oci.tar.zst":                     "inference-image",
		"appliance-inference-0.6.5.tgz":                     "inference-chart",
		"appliance-metadata-bundle-2.4.0.0.tar.zst":         "metadata-bundle-bytes",
		"configuration.schema.json":                         `{"type":"object"}`,
		"compatibility.json":                                `{"k3sVersion":"v1.30.4+k3s1"}`,
		"checksums.txt":                                     "checksums",
		"sbom/appliance.spdx.json":                          "{}",
		"provenance/appliance.provenance.json":              "{}",
		"notices/THIRD-PARTY-NOTICES.txt":                   "notice",
		"tests/conformance.tar.zst":                         "tests",
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
		"schemaVersion": 1,
		"codeVersion":   "2.4.0",
		"releaseId":     "release-2.4.0",
		"generatedAt":   "2026-07-06T00:00:00Z",
		"artifacts": map[string]any{
			"controlPlaneImage":     map[string]any{"path": "control-plane.oci.tar.zst", "digest": digestOf("control-plane.oci.tar.zst"), "sizeBytes": len("control-plane"), "imageReference": "internal/control-plane:2.4.0"},
			"uiImage":               map[string]any{"path": "appliance-ui.oci.tar.zst", "digest": digestOf("appliance-ui.oci.tar.zst"), "sizeBytes": len("ui-image"), "imageReference": "internal/appliance-ui:2.4.0"},
			"hostAgentImage":        map[string]any{"path": "appliance-host-agent.oci.tar.zst", "digest": digestOf("appliance-host-agent.oci.tar.zst"), "sizeBytes": len("host-agent-image"), "imageReference": "registry.local/appliance-host-agent@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
			"hostAgentBinary":       map[string]any{"path": "appliance-host-agentd", "digest": digestOf("appliance-host-agentd"), "sizeBytes": len("host-agentd")},
			"hostPackages":          map[string]any{"path": "host-packages", "manifestDigest": dirDigestOf("host-packages")},
			"applianceChart":        map[string]any{"path": "appliance-chart-2.4.0.tgz", "digest": digestOf("appliance-chart-2.4.0.tgz"), "sizeBytes": len("chart")},
			"artifactServerImage":   map[string]any{"path": "artifact-server.oci.tar.zst", "digest": digestOf("artifact-server.oci.tar.zst"), "sizeBytes": len("artifact-server-image"), "imageReference": "registry.local/artifact-server@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			"artifactServerChart":   map[string]any{"path": "appliance-registry-2.1.7.tgz", "digest": digestOf("appliance-registry-2.1.7.tgz"), "sizeBytes": len("artifact-server-chart")},
			"dnsImage":              map[string]any{"path": "coredns.oci.tar.zst", "digest": digestOf("coredns.oci.tar.zst"), "sizeBytes": len("dns-image"), "imageReference": "registry.local/coredns@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
			"dnsChart":              map[string]any{"path": "appliance-dns-1.14.4.tgz", "digest": digestOf("appliance-dns-1.14.4.tgz"), "sizeBytes": len("dns-chart")},
			"blobStorageImage":      map[string]any{"path": "blob-storage.oci.tar.zst", "digest": digestOf("blob-storage.oci.tar.zst"), "sizeBytes": len("blob-storage-image"), "imageReference": "registry.local/blob-storage@sha256:abababababababababababababababababababababababababababababababab"},
			"inferenceRuntimeImage": map[string]any{"path": "inference-runtime.oci.tar.zst", "digest": digestOf("inference-runtime.oci.tar.zst"), "sizeBytes": len("inference-image"), "imageReference": "registry.local/inference-runtime@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
			"inferenceChart":        map[string]any{"path": "appliance-inference-0.6.5.tgz", "digest": digestOf("appliance-inference-0.6.5.tgz"), "sizeBytes": len("inference-chart")},
			"metadataBundle":        map[string]any{"path": "appliance-metadata-bundle-2.4.0.0.tar.zst", "digest": digestOf("appliance-metadata-bundle-2.4.0.0.tar.zst"), "sizeBytes": len("metadata-bundle-bytes")},
			"configurationSchema":   map[string]any{"path": "configuration.schema.json", "digest": digestOf("configuration.schema.json"), "sizeBytes": len(`{"type":"object"}`)},
			"compatibility":         map[string]any{"path": "compatibility.json", "digest": digestOf("compatibility.json"), "sizeBytes": len(`{"k3sVersion":"v1.30.4+k3s1"}`)},
			"checksums":             map[string]any{"path": "checksums.txt", "digest": digestOf("checksums.txt"), "sizeBytes": len("checksums")},
			"sbom":                  map[string]any{"path": "sbom", "manifestDigest": dirDigestOf("sbom")},
			"provenance":            map[string]any{"path": "provenance", "manifestDigest": dirDigestOf("provenance")},
			"notices":               map[string]any{"path": "notices", "manifestDigest": dirDigestOf("notices")},
			"tests":                 map[string]any{"path": "tests", "manifestDigest": dirDigestOf("tests")},
		},
		"compatibility": map[string]any{
			"k3sVersion":              "v1.30.4+k3s1",
			"chartVersion":            "2.4.0",
			"artifactServerVersion":   "2.1.7",
			"dnsVersion":              "1.14.4",
			"inferenceVersion":        "0.6.5",
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
		BundleVersion:         "9.1.0",
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
	if b.BundleVersion != "9.1.0" || b.ReleaseID != "release-2.4.0" {
		t.Fatalf("unexpected bundle metadata: %+v", b)
	}
	if _, err := os.Stat(filepath.Join(result.BundleDir, "configuration", "configuration.schema.json")); err != nil {
		t.Fatalf("expected configuration schema to be carried into the bundle: %v", err)
	}
	if _, err := os.Stat(filepath.Join(result.BundleDir, "configuration", "appliance-catalog.json")); err != nil {
		t.Fatalf("expected appliance catalog to be carried into the bundle: %v", err)
	}
	if _, err := os.Stat(filepath.Join(result.BundleDir, "oci-images", "appliance-ui.oci.tar.zst")); err != nil {
		t.Fatalf("expected UI image to be carried into the bundle: %v", err)
	}
	if _, err := os.Stat(filepath.Join(result.BundleDir, "oci-images", "appliance-host-agent.oci.tar.zst")); err != nil {
		t.Fatalf("expected host-agent image to be carried into the bundle: %v", err)
	}
	if _, err := os.Stat(filepath.Join(result.BundleDir, "bin", "appliance-host-agentd")); err != nil {
		t.Fatalf("expected host-agent binary to be carried into the bundle: %v", err)
	}
	if _, err := os.Stat(filepath.Join(result.BundleDir, "host-packages", "ubuntu", "24.04", "amd64", "avahi-daemon.deb")); err != nil {
		t.Fatalf("expected host packages to be carried into the bundle: %v", err)
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
		BundleVersion:         "9.1.0",
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

func TestAssemblePackFoundationExcludesWorkflowAndInference(t *testing.T) {
	releaseInputDir := buildReleaseInputDir(t)
	staging := t.TempDir()
	writeTestFile(t, staging, "zonctl", "zonctl-binary", 0o750)
	writeTestFile(t, staging, "k3s", "k3s-binary", 0o750)
	writeTestFile(t, staging, "install.sh", "#!/bin/sh\n", 0o750)
	writeTestFile(t, staging, "k3s-airgap-images.tar", "k3s images", 0o640)
	writeTestFile(t, staging, "control-plane.tar", "app image", 0o640)
	writeTestFile(t, staging, "chart.tgz", "chart", 0o640)
	writeTestFile(t, staging, "values.yaml", "replicaCount: 1\n", 0o640)
	writeTestFile(t, staging, "workflows-chart.tgz", "workflows", 0o640)
	writeTestFile(t, staging, "workflow-controller.oci.tar.zst", "controller", 0o640)
	writeTestFile(t, staging, "workspace-provisioner.oci.tar.zst", "provisioner", 0o640)
	writeTestFile(t, staging, "workflows.argoproj.io.yaml", "crd", 0o640)

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
		BundleVersion:         "9.1.0",
		ReleaseInputDir:       releaseInputDir,
		BundleDir:             filepath.Join(t.TempDir(), "bundle-base"),
		SigningKeyID:          "release-signing-key",
		SigningPrivateKeyPath: privateKeyPath,
		HostBaseline:          releasebundle.HostBaseline{OS: "ubuntu", OSVersion: "24.04", Arch: "amd64"},
		Pack:                  releasebundle.PackFoundation,
		Entries: []releasebundle.EntryConfig{
			{SourcePath: filepath.Join(staging, "zonctl"), TargetPath: "zonctl", Component: "appliance", Executable: true},
			{SourcePath: filepath.Join(staging, "k3s"), TargetPath: "k3s/binary/k3s", Component: "k3s-binary", Executable: true},
			{SourcePath: filepath.Join(staging, "install.sh"), TargetPath: "k3s/install/install.sh", Component: "k3s-install", Executable: true},
			{SourcePath: filepath.Join(staging, "k3s-airgap-images.tar"), TargetPath: "k3s/images/k3s-airgap-images.tar", Component: "k3s-images"},
			{SourcePath: filepath.Join(staging, "control-plane.tar"), TargetPath: "oci-images/control-plane.tar", Component: "oci-images", ImageReference: "internal/control-plane:2.4.0"},
			{SourcePath: filepath.Join(staging, "chart.tgz"), TargetPath: "charts/appliance-chart-2.4.0.tgz", Component: "chart"},
			{SourcePath: filepath.Join(staging, "values.yaml"), TargetPath: "configuration/values.yaml", Component: "configuration"},
			{SourcePath: filepath.Join(staging, "workflows-chart.tgz"), TargetPath: "charts/workflows-chart-1.0.0.tgz", Component: "chart"},
			{SourcePath: filepath.Join(staging, "workflow-controller.oci.tar.zst"), TargetPath: "oci-images/workflow-controller.oci.tar.zst", Component: "oci-images", ImageReference: "quay.io/argoproj/workflow-controller:v3.5.0"},
			{SourcePath: filepath.Join(staging, "workspace-provisioner.oci.tar.zst"), TargetPath: "oci-images/workspace-provisioner.oci.tar.zst", Component: "oci-images", ImageReference: "registry.local/workspace-provisioner@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
			{SourcePath: filepath.Join(staging, "workflows.argoproj.io.yaml"), TargetPath: "kubernetes/crds/workflows.argoproj.io.yaml", Component: "kubernetes-crds"},
		},
	}

	result, err := releasebundle.Assemble(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected foundation pack assembly to succeed, got: %v", err)
	}
	if _, err := os.Stat(filepath.Join(result.BundleDir, "charts", "workflows-chart-1.0.0.tgz")); !os.IsNotExist(err) {
		t.Fatalf("foundation pack must exclude workflows chart, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(result.BundleDir, "oci-images", "inference-runtime.oci.tar.zst")); !os.IsNotExist(err) {
		t.Fatalf("foundation pack must exclude inference image, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(result.BundleDir, "oci-images", "appliance-ui.oci.tar.zst")); err != nil {
		t.Fatalf("foundation pack must keep UI image: %v", err)
	}
}

func TestAssemblePackInferenceOnly(t *testing.T) {
	releaseInputDir := buildReleaseInputDir(t)
	staging := t.TempDir()
	writeTestFile(t, staging, "zonctl", "zonctl-binary", 0o750)
	writeTestFile(t, staging, "k3s", "k3s-binary", 0o750)
	writeTestFile(t, staging, "control-plane.tar", "app image", 0o640)
	writeTestFile(t, staging, "chart.tgz", "chart", 0o640)
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
		BundleVersion:         "9.1.0",
		ReleaseInputDir:       releaseInputDir,
		BundleDir:             filepath.Join(t.TempDir(), "bundle-inference"),
		SigningKeyID:          "release-signing-key",
		SigningPrivateKeyPath: privateKeyPath,
		HostBaseline:          releasebundle.HostBaseline{OS: "ubuntu", OSVersion: "24.04", Arch: "amd64"},
		Pack:                  releasebundle.PackInference,
		Entries: []releasebundle.EntryConfig{
			{SourcePath: filepath.Join(staging, "zonctl"), TargetPath: "zonctl", Component: "appliance", Executable: true},
			{SourcePath: filepath.Join(staging, "k3s"), TargetPath: "k3s/binary/k3s", Component: "k3s-binary", Executable: true},
			{SourcePath: filepath.Join(staging, "control-plane.tar"), TargetPath: "oci-images/control-plane.tar", Component: "oci-images", ImageReference: "internal/control-plane:2.4.0"},
			{SourcePath: filepath.Join(staging, "chart.tgz"), TargetPath: "charts/appliance-chart-2.4.0.tgz", Component: "chart"},
			{SourcePath: filepath.Join(staging, "values.yaml"), TargetPath: "configuration/values.yaml", Component: "configuration"},
		},
	}

	result, err := releasebundle.Assemble(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected inference pack assembly to succeed, got: %v", err)
	}
	if _, err := os.Stat(filepath.Join(result.BundleDir, "oci-images", "inference-runtime.oci.tar.zst")); err != nil {
		t.Fatalf("inference pack must include runtime image: %v", err)
	}
	if _, err := os.Stat(filepath.Join(result.BundleDir, "chart", "appliance-inference-0.6.5.tgz")); err != nil {
		t.Fatalf("inference pack must include inference chart: %v", err)
	}
	if _, err := os.Stat(filepath.Join(result.BundleDir, "zonctl")); !os.IsNotExist(err) {
		t.Fatalf("inference pack must not include foundation appliance binary, stat err=%v", err)
	}
}
