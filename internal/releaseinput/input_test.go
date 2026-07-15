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
	return buildReleaseInputWithCodeVersion(t, "2.4.0")
}

func buildReleaseInputWithCodeVersion(t *testing.T, codeVersion string) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "control-plane.oci.tar.zst", "control-plane-bytes")
	writeFile(t, root, "appliance-ui.oci.tar.zst", "ui-bytes")
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
		"codeVersion":   codeVersion,
		"releaseId":     "release-" + codeVersion,
		"generatedAt":   "2026-07-06T00:00:00Z",
		"artifacts": map[string]any{
			"controlPlaneImage":   map[string]any{"path": "control-plane.oci.tar.zst", "digest": digestOf("control-plane.oci.tar.zst"), "sizeBytes": len("control-plane-bytes"), "imageReference": "localhost/appliance-control-plane:2.4.0"},
			"uiImage":             map[string]any{"path": "appliance-ui.oci.tar.zst", "digest": digestOf("appliance-ui.oci.tar.zst"), "sizeBytes": len("ui-bytes"), "imageReference": "localhost/appliance-ui:2.4.0"},
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
	if in.Artifacts.ControlPlaneImage.ImageReference != "localhost/appliance-control-plane:2.4.0" {
		t.Fatalf("unexpected control-plane image reference: %+v", in.Artifacts.ControlPlaneImage)
	}
	if in.Artifacts.UIImage.ImageReference != "localhost/appliance-ui:2.4.0" {
		t.Fatalf("unexpected UI image reference: %+v", in.Artifacts.UIImage)
	}
	if len(checks) == 0 {
		t.Fatal("expected evidence checks")
	}
}

func TestLoad_ValidReleaseInputWithOptionalArgoArtifacts(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "control-plane.oci.tar.zst", "control-plane-bytes")
	writeFile(t, root, "appliance-ui.oci.tar.zst", "ui-bytes")
	writeFile(t, root, "appliance-chart-2.4.0.tgz", "chart-bytes")
	writeFile(t, root, "configuration.schema.json", `{"type":"object"}`)
	writeFile(t, root, "compatibility.json", `{"k3sVersion":"v1.30.4+k3s1","argoVersion":"3.5.10"}`)
	writeFile(t, root, "checksums.txt", "sha256sum entries")
	writeFile(t, root, "sbom/appliance.spdx.json", "{}")
	writeFile(t, root, "provenance/appliance.provenance.json", "{}")
	writeFile(t, root, "notices/THIRD-PARTY-NOTICES.txt", "notice")
	writeFile(t, root, "tests/conformance.tar.zst", "tests")
	writeFile(t, root, "argo-workflows-chart-3.5.10.tgz", "argo-chart-bytes")
	writeFile(t, root, "argo-controller.oci.tar.zst", "argo-controller")
	writeFile(t, root, "argo-executor.oci.tar.zst", "argo-executor")
	writeFile(t, root, "buildah.oci.tar.zst", "buildah-image")
	writeFile(t, root, "argo-crds/workflows.argoproj.io.yaml", "kind: CustomResourceDefinition\n")

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
			"controlPlaneImage":   map[string]any{"path": "control-plane.oci.tar.zst", "digest": digestOf("control-plane.oci.tar.zst"), "sizeBytes": len("control-plane-bytes"), "imageReference": "localhost/appliance-control-plane:2.4.0"},
			"uiImage":             map[string]any{"path": "appliance-ui.oci.tar.zst", "digest": digestOf("appliance-ui.oci.tar.zst"), "sizeBytes": len("ui-bytes"), "imageReference": "localhost/appliance-ui:2.4.0"},
			"applianceChart":      map[string]any{"path": "appliance-chart-2.4.0.tgz", "digest": digestOf("appliance-chart-2.4.0.tgz"), "sizeBytes": len("chart-bytes")},
			"configurationSchema": map[string]any{"path": "configuration.schema.json", "digest": digestOf("configuration.schema.json"), "sizeBytes": len(`{"type":"object"}`)},
			"compatibility":       map[string]any{"path": "compatibility.json", "digest": digestOf("compatibility.json"), "sizeBytes": len(`{"k3sVersion":"v1.30.4+k3s1","argoVersion":"3.5.10"}`)},
			"checksums":           map[string]any{"path": "checksums.txt", "digest": digestOf("checksums.txt"), "sizeBytes": len("sha256sum entries")},
			"sbom":                map[string]any{"path": "sbom", "manifestDigest": dirDigestOf("sbom")},
			"provenance":          map[string]any{"path": "provenance", "manifestDigest": dirDigestOf("provenance")},
			"notices":             map[string]any{"path": "notices", "manifestDigest": dirDigestOf("notices")},
			"tests":               map[string]any{"path": "tests", "manifestDigest": dirDigestOf("tests")},
			"argoWorkflowsChart":  map[string]any{"path": "argo-workflows-chart-3.5.10.tgz", "digest": digestOf("argo-workflows-chart-3.5.10.tgz"), "sizeBytes": len("argo-chart-bytes")},
			"argoCRDs":            map[string]any{"path": "argo-crds", "manifestDigest": dirDigestOf("argo-crds")},
			"argoControllerImage": map[string]any{"path": "argo-controller.oci.tar.zst", "digest": digestOf("argo-controller.oci.tar.zst"), "sizeBytes": len("argo-controller"), "imageReference": "quay.io/argoproj/workflow-controller:v3.5.10"},
			"argoExecutorImage":   map[string]any{"path": "argo-executor.oci.tar.zst", "digest": digestOf("argo-executor.oci.tar.zst"), "sizeBytes": len("argo-executor"), "imageReference": "quay.io/argoproj/argoexec:v3.5.10"},
			"extraOCIImages":      []any{map[string]any{"path": "buildah.oci.tar.zst", "digest": digestOf("buildah.oci.tar.zst"), "sizeBytes": len("buildah-image"), "imageReference": "registry.local/buildah@sha256:approved"}},
		},
		"compatibility": map[string]any{
			"k3sVersion":   "v1.30.4+k3s1",
			"chartVersion": "2.4.0",
			"argoVersion":  "3.5.10",
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
		t.Fatalf("expected valid release input with Argo artifacts, got: %v", err)
	}
	if in.Compatibility.ArgoVersion != "3.5.10" {
		t.Fatalf("expected argoVersion 3.5.10, got %+v", in.Compatibility)
	}
	if filepath.Base(in.Artifacts.ArgoWorkflowsChart.Path) != "argo-workflows-chart-3.5.10.tgz" {
		t.Fatalf("unexpected argo chart artifact: %+v", in.Artifacts.ArgoWorkflowsChart)
	}
	if filepath.Base(in.Artifacts.ArgoControllerImage.Path) != "argo-controller.oci.tar.zst" {
		t.Fatalf("unexpected argo controller image artifact: %+v", in.Artifacts.ArgoControllerImage)
	}
	if filepath.Base(in.Artifacts.ArgoCRDs.Path) != "argo-crds" {
		t.Fatalf("unexpected argo crd artifact: %+v", in.Artifacts.ArgoCRDs)
	}
	if len(in.Artifacts.ExtraOCIImages) != 1 || in.Artifacts.ExtraOCIImages[0].ImageReference != "registry.local/buildah@sha256:approved" {
		t.Fatalf("unexpected extra OCI image artifacts: %+v", in.Artifacts.ExtraOCIImages)
	}
}

func TestLoad_ValidReleaseInputWithRepoDerivedCodeVersion(t *testing.T) {
	root := buildReleaseInputWithCodeVersion(t, "v0.1.0-3-ge6a4243-dirty")
	in, _, err := releaseinput.Load(root)
	if err != nil {
		t.Fatalf("expected repo-derived code version to validate, got: %v", err)
	}
	if in.CodeVersion != "v0.1.0-3-ge6a4243-dirty" || in.ReleaseID != "release-v0.1.0-3-ge6a4243-dirty" {
		t.Fatalf("unexpected parsed metadata: %+v", in)
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
	writeFile(t, root, "appliance-ui.oci.tar.zst", "ui-bytes")
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
			"controlPlaneImage":   map[string]any{"path": "control-plane.oci.tar.zst", "digest": digestOf("control-plane.oci.tar.zst"), "sizeBytes": len("control-plane-bytes"), "imageReference": "localhost/appliance-control-plane:2.4.0"},
			"uiImage":             map[string]any{"path": "appliance-ui.oci.tar.zst", "digest": digestOf("appliance-ui.oci.tar.zst"), "sizeBytes": len("ui-bytes"), "imageReference": "localhost/appliance-ui:2.4.0"},
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
