package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/releasebundle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/releaseinput"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

func writeReleaseFixtureFile(t *testing.T, root, rel, content string, mode os.FileMode) string {
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

func buildReleaseInputDirForCLI(t *testing.T) string {
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
		writeReleaseFixtureFile(t, root, rel, content, 0o640)
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

func TestRun_AssembleBundleAndVerifyBundle(t *testing.T) {
	releaseInputDir := buildReleaseInputDirForCLI(t)
	staging := t.TempDir()
	writeReleaseFixtureFile(t, staging, "zonctl", "zonctl-binary", 0o750)
	writeReleaseFixtureFile(t, staging, "k3s", "k3s-binary", 0o750)
	writeReleaseFixtureFile(t, staging, "install.sh", "#!/bin/sh\n", 0o750)
	writeReleaseFixtureFile(t, staging, "k3s-airgap-images.tar", "k3s images", 0o640)
	writeReleaseFixtureFile(t, staging, "control-plane.tar", "app image", 0o640)
	writeReleaseFixtureFile(t, staging, "chart.tgz", "chart", 0o640)
	writeReleaseFixtureFile(t, staging, "values.yaml", "replicaCount: 1\n", 0o640)

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
	configPath := filepath.Join(t.TempDir(), "bundle-assembly.json")
	configBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configBytes, 0o640); err != nil {
		t.Fatal(err)
	}

	out, code := captureStdout(t, func() int {
		return run([]string{"assemble-bundle", "--output", "json", "--config", configPath})
	})
	if code != 0 {
		t.Fatalf("expected assemble-bundle to succeed, got code %d with output %s", code, out)
	}

	var assembleResult struct {
		Command string `json:"command"`
		Data    struct {
			BundleDir     string `json:"bundleDir"`
			PublicKeyPath string `json:"publicKeyPath"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &assembleResult); err != nil {
		t.Fatalf("expected assemble-bundle JSON output, got: %s (%v)", out, err)
	}
	if assembleResult.Command != "assemble-bundle" {
		t.Fatalf("expected assemble-bundle command result, got %+v", assembleResult)
	}
	if _, err := os.Stat(filepath.Join(assembleResult.Data.BundleDir, "release-manifest.json")); err != nil {
		t.Fatalf("expected assembled release-manifest.json, got: %v", err)
	}

	out, code = captureStdout(t, func() int {
		return run([]string{"verify-bundle", "--output", "json", "--bundle-dir", assembleResult.Data.BundleDir, "--public-key", assembleResult.Data.PublicKeyPath})
	})
	if code != 0 {
		t.Fatalf("expected verify-bundle to succeed, got code %d with output %s", code, out)
	}

	var verifyResult struct {
		Command string `json:"command"`
		Data    struct {
			BundleVersion string `json:"bundleVersion"`
			ReleaseID     string `json:"releaseId"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &verifyResult); err != nil {
		t.Fatalf("expected verify-bundle JSON output, got: %s (%v)", out, err)
	}
	if verifyResult.Command != "verify-bundle" {
		t.Fatalf("expected verify-bundle command result, got %+v", verifyResult)
	}
	if verifyResult.Data.BundleVersion != "9.1.0" || verifyResult.Data.ReleaseID != "release-2.4.0" {
		t.Fatalf("unexpected verify-bundle metadata: %+v", verifyResult)
	}
}

func TestRun_AssembleBundleRequiresConfig(t *testing.T) {
	out, code := captureStdout(t, func() int {
		return run([]string{"assemble-bundle", "--output", "json"})
	})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !json.Valid([]byte(out)) {
		t.Fatalf("expected JSON output, got: %s", out)
	}
	if !containsAll(out, `"command":"assemble-bundle"`, `"message":"assemble-bundle: --config is required"`) {
		t.Fatalf("expected missing-config error in output, got: %s", out)
	}
}

func TestRun_VerifyBundleRequiresInputs(t *testing.T) {
	out, code := captureStdout(t, func() int {
		return run([]string{"verify-bundle", "--output", "json"})
	})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !json.Valid([]byte(out)) {
		t.Fatalf("expected JSON output, got: %s", out)
	}
	if !containsAll(out, `"command":"verify-bundle"`, `"message":"verify-bundle: --bundle-dir and --public-key are required"`) {
		t.Fatalf("expected missing-input error in output, got: %s", out)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}
