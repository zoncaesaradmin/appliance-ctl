package releaseinput_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/releaseinput"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

func writeFile(t *testing.T, root, rel, content string) string {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func buildReleaseInput(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "control-plane.oci.tar.zst", "control-plane-bytes")
	writeFile(t, root, "appliance-chart-2.4.0.tgz", "chart-bytes")
	writeFile(t, root, "configuration.schema.json", `{"type":"object"}`)
	writeFile(t, root, "compatibility.json", `{"k3sVersion":"v1.30.4+k3s1"}`)
	writeFile(t, root, "checksums.txt", "sha256sum entries")
	writeFile(t, root, "sbom/appliance.spdx.json", "{}")
	writeFile(t, root, "provenance/appliance.provenance.json", "{}")
	writeFile(t, root, "notices/THIRD-PARTY-NOTICES.txt", "notice")
	writeFile(t, root, "tests/conformance.tar.zst", "tests")

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
			"controlPlaneImage":   map[string]any{"path": "control-plane.oci.tar.zst", "digest": digestOf("control-plane.oci.tar.zst"), "sizeBytes": len("control-plane-bytes")},
			"applianceChart":      map[string]any{"path": "appliance-chart-2.4.0.tgz", "digest": digestOf("appliance-chart-2.4.0.tgz"), "sizeBytes": len("chart-bytes")},
			"configurationSchema": map[string]any{"path": "configuration.schema.json", "digest": digestOf("configuration.schema.json"), "sizeBytes": len(`{"type":"object"}`)},
			"compatibility":       map[string]any{"path": "compatibility.json", "digest": digestOf("compatibility.json"), "sizeBytes": len(`{"k3sVersion":"v1.30.4+k3s1"}`)},
			"checksums":           map[string]any{"path": "checksums.txt", "digest": digestOf("checksums.txt"), "sizeBytes": len("sha256sum entries")},
			"sbom":                map[string]any{"path": "sbom", "manifestDigest": dirDigestOf("sbom")},
			"provenance":          map[string]any{"path": "provenance", "manifestDigest": dirDigestOf("provenance")},
			"notices":             map[string]any{"path": "notices", "manifestDigest": dirDigestOf("notices")},
			"tests":               map[string]any{"path": "tests", "manifestDigest": dirDigestOf("tests")},
		},
		"compatibility": map[string]any{
			"k3sVersion":              "v1.30.4+k3s1",
			"chartVersion":            "2.4.0",
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

func TestLoad_ValidReleaseInput(t *testing.T) {
	root := buildReleaseInput(t)
	in, checks, err := releaseinput.Load(root)
	if err != nil {
		t.Fatalf("expected valid release input, got: %v", err)
	}
	if in.CodeVersion != "2.4.0" || in.ReleaseID != "release-2.4.0" {
		t.Fatalf("unexpected parsed metadata: %+v", in)
	}
	if len(checks) == 0 {
		t.Fatal("expected evidence checks")
	}
}

func TestLoad_TamperedDirectoryFailsClosed(t *testing.T) {
	root := buildReleaseInput(t)
	if err := os.WriteFile(filepath.Join(root, "sbom", "appliance.spdx.json"), []byte(`{"tampered":true}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := releaseinput.Load(root); err == nil {
		t.Fatal("expected tampered directory manifest to fail verification")
	}
}

func TestLoad_ValidReleaseInputWithoutOptionalUpgradeSources(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "control-plane.oci.tar.zst", "control-plane-bytes")
	writeFile(t, root, "appliance-chart-2.4.0.tgz", "chart-bytes")
	writeFile(t, root, "configuration.schema.json", `{"type":"object"}`)
	writeFile(t, root, "compatibility.json", `{"k3sVersion":"v1.30.4+k3s1"}`)
	writeFile(t, root, "checksums.txt", "sha256sum entries")
	writeFile(t, root, "sbom/appliance.spdx.json", "{}")
	writeFile(t, root, "provenance/appliance.provenance.json", "{}")
	writeFile(t, root, "notices/THIRD-PARTY-NOTICES.txt", "notice")
	writeFile(t, root, "tests/conformance.tar.zst", "tests")

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
			"controlPlaneImage":   map[string]any{"path": "control-plane.oci.tar.zst", "digest": digestOf("control-plane.oci.tar.zst"), "sizeBytes": len("control-plane-bytes")},
			"applianceChart":      map[string]any{"path": "appliance-chart-2.4.0.tgz", "digest": digestOf("appliance-chart-2.4.0.tgz"), "sizeBytes": len("chart-bytes")},
			"configurationSchema": map[string]any{"path": "configuration.schema.json", "digest": digestOf("configuration.schema.json"), "sizeBytes": len(`{"type":"object"}`)},
			"compatibility":       map[string]any{"path": "compatibility.json", "digest": digestOf("compatibility.json"), "sizeBytes": len(`{"k3sVersion":"v1.30.4+k3s1"}`)},
			"checksums":           map[string]any{"path": "checksums.txt", "digest": digestOf("checksums.txt"), "sizeBytes": len("sha256sum entries")},
			"sbom":                map[string]any{"path": "sbom", "manifestDigest": dirDigestOf("sbom")},
			"provenance":          map[string]any{"path": "provenance", "manifestDigest": dirDigestOf("provenance")},
			"notices":             map[string]any{"path": "notices", "manifestDigest": dirDigestOf("notices")},
			"tests":               map[string]any{"path": "tests", "manifestDigest": dirDigestOf("tests")},
		},
		"compatibility": map[string]any{
			"k3sVersion":   "v1.30.4+k3s1",
			"chartVersion": "2.4.0",
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "release-input.json"), data, 0o640); err != nil {
		t.Fatal(err)
	}

	in, _, err := releaseinput.Load(root)
	if err != nil {
		t.Fatalf("expected release input without optional upgrade sources to load, got: %v", err)
	}
	if len(in.Compatibility.SupportedUpgradeSources) != 0 {
		t.Fatalf("expected no supported upgrade sources, got %+v", in.Compatibility.SupportedUpgradeSources)
	}
}
