package install_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/install"
	"github.com/zoncaesaradmin/appliance-ctl/internal/metadatabundle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

const testMetadataBundleRel = "artifacts/appliance-metadata-bundle-2.4.0.0.tar.zst"

func appendTestMetadataBundleManifestEntry(t *testing.T, dir string, manifestEntries *[]map[string]any) {
	t.Helper()
	full := filepath.Join(dir, testMetadataBundleRel)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := metadatabundle.WriteInstallTestArchive(full, "2.4.0.0"); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := verify.Digest(full)
	if err != nil {
		t.Fatal(err)
	}
	*manifestEntries = append(*manifestEntries, map[string]any{
		"path": testMetadataBundleRel, "component": "artifacts", "digest": digest, "sizeBytes": len(content),
	})
}

func sourceFixtureImageReference(rel string) string {
	switch rel {
	case "oci-images/appliance-host-agent.tar":
		return "registry.local/appliance-host-agent@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	case "oci-images/blob-storage.tar":
		return "registry.local/blob-storage@sha256:abababababababababababababababababababababababababababababababab"
	}
	return ""
}

func TestOfflineSource_PrefersValuesYAMLWhenMultipleConfigurationEntriesExist(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"bin/zonctl-real":                                   "fake zonctl binary",
		"bin/helm":                                          "fake helm binary",
		"bin/appliance-host-agentd":                         "fake appliance host agent daemon",
		"k3s/binary/k3s":                                    "fake k3s binary",
		"charts/appliance-chart-2.4.0.tgz":                  "fake chart",
		"configuration/appliance-catalog.json":              `{"version":"appliance.catalog/v1alpha1","profiles":[{"name":"core","capabilities":["base","host"]}],"modules":[{"name":"host-agent","kind":"platform","requiredCapabilities":["host"],"executionMode":"host-agent","entitlementKey":"host-agent","baseURL":"http://host-agent.ace-apps.svc.cluster.local:8080","securityClass":"host-privileged"}]}`,
		"configuration/configuration.schema.json":           `{"type":"object"}`,
		"configuration/values.yaml":                         "replicaCount: 1\n",
		"host-packages/ubuntu/24.04/amd64/avahi-daemon.deb": "fake avahi deb",
		"oci-images/appliance-host-agent.tar":               "fake appliance host agent image",
		"oci-images/blob-storage.tar":                       "fake blob storage image",
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
		case rel == "bin/zonctl-real", rel == "bin/helm", rel == "bin/appliance-host-agentd":
			component = "appliance"
		case rel == "k3s/binary/k3s":
			component = "k3s-binary"
		case rel == "charts/appliance-chart-2.4.0.tgz":
			component = "chart"
		case strings.HasPrefix(rel, "host-packages/"):
			component = "host-packages"
		case strings.HasPrefix(rel, "artifacts/"):
			component = "artifacts"
		case strings.HasPrefix(rel, "oci-images/"):
			component = "oci-images"
		}
		entry := map[string]any{
			"path": rel, "component": component, "digest": digest, "sizeBytes": len(content),
		}
		if imageReference := sourceFixtureImageReference(rel); imageReference != "" {
			entry["imageReference"] = imageReference
		}
		manifestEntries = append(manifestEntries, entry)
	}
	appendTestMetadataBundleManifestEntry(t, dir, &manifestEntries)

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
	resolved, _, err := source.Resolve(context.Background(), "core")
	if err != nil {
		t.Fatalf("expected bundle to resolve, got: %v", err)
	}
	if resolved.BundleVersion != "2.4.0" {
		t.Fatalf("expected bundle version 2.4.0, got %s", resolved.BundleVersion)
	}
	if resolved.HostBaseline.OS != "ubuntu" || resolved.HostBaseline.OSVersion != "24.04" || resolved.HostBaseline.Arch != "amd64" {
		t.Fatalf("unexpected host baseline: %+v", resolved.HostBaseline)
	}
	if filepath.Base(resolved.ZonctlBinaryPath) != "zonctl-real" {
		t.Fatalf("expected zonctl-real to be selected, got %s", resolved.ZonctlBinaryPath)
	}
	if len(resolved.HelperBinaryPaths) != 1 || filepath.Base(resolved.HelperBinaryPaths[0]) != "helm" {
		t.Fatalf("expected durable helm helper path, got %#v", resolved.HelperBinaryPaths)
	}
	if filepath.Base(resolved.ConfigurationPath) != "values.yaml" {
		t.Fatalf("expected values.yaml to be selected, got %s", resolved.ConfigurationPath)
	}
	if !productconfig.HasCapabilityInCatalog(resolved.EffectiveProfile, productconfig.CapabilityFiles, resolved.ProfileCatalog) {
		t.Fatal("expected metadata profile catalog to enable files for the resolved core profile")
	}
}

func TestOfflineSource_ResolvesBothControlPlaneAndUIImageArchives(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"bin/zonctl-real":                  "fake zonctl binary",
		"bin/helm":                         "fake helm binary",
		"bin/appliance-host-agentd":        "fake appliance host agent daemon",
		"k3s/binary/k3s":                   "fake k3s binary",
		"charts/appliance-chart-2.4.0.tgz": "fake appliance chart",
		"configuration/values.yaml":        "replicaCount: 1\n",
		"host-packages/ubuntu/24.04/amd64/avahi-daemon.deb": "fake avahi deb",
		"oci-images/control-plane.tar":                      "fake control plane image",
		"oci-images/appliance-ui.tar":                       "fake appliance ui image",
		"oci-images/appliance-host-agent.tar":               "fake appliance host agent image",
		"oci-images/blob-storage.tar":                       "fake blob storage image",
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
		entry := map[string]any{
			"path": rel, "digest": digest, "sizeBytes": len(content),
		}
		switch {
		case rel == "bin/zonctl-real", rel == "bin/helm", rel == "bin/appliance-host-agentd":
			entry["component"] = "appliance"
		case rel == "k3s/binary/k3s":
			entry["component"] = "k3s-binary"
		case rel == "charts/appliance-chart-2.4.0.tgz":
			entry["component"] = "chart"
		case rel == "configuration/values.yaml":
			entry["component"] = "configuration"
		case strings.HasPrefix(rel, "host-packages/"):
			entry["component"] = "host-packages"
		case strings.HasPrefix(rel, "artifacts/"):
			entry["component"] = "artifacts"
		default:
			entry["component"] = "oci-images"
		}
		switch rel {
		case "oci-images/control-plane.tar":
			entry["imageReference"] = "internal/control-plane:2.4.0"
		case "oci-images/appliance-ui.tar":
			entry["imageReference"] = "internal/appliance-ui:2.4.0"
		case "oci-images/appliance-host-agent.tar":
			entry["imageReference"] = "registry.local/appliance-host-agent@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		case "oci-images/blob-storage.tar":
			entry["imageReference"] = sourceFixtureImageReference(rel)
		}
		manifestEntries = append(manifestEntries, entry)
	}
	appendTestMetadataBundleManifestEntry(t, dir, &manifestEntries)

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
	resolved, _, err := source.Resolve(context.Background(), "core")
	if err != nil {
		t.Fatalf("expected bundle to resolve, got: %v", err)
	}
	if len(resolved.OCIImages) != 4 {
		t.Fatalf("OCIImages length = %d, want 4", len(resolved.OCIImages))
	}

	names := []string{resolved.OCIImages[0].Name, resolved.OCIImages[1].Name, resolved.OCIImages[2].Name, resolved.OCIImages[3].Name}
	if !strings.Contains(strings.Join(names, ","), "internal/control-plane:2.4.0") {
		t.Fatalf("resolved OCI images missing control-plane reference: %v", names)
	}
	if !strings.Contains(strings.Join(names, ","), "internal/appliance-ui:2.4.0") {
		t.Fatalf("resolved OCI images missing UI reference: %v", names)
	}
	if !strings.Contains(strings.Join(names, ","), "registry.local/appliance-host-agent@sha256:") {
		t.Fatalf("resolved OCI images missing host agent reference: %v", names)
	}
	if !strings.Contains(strings.Join(names, ","), "registry.local/blob-storage@sha256:") {
		t.Fatalf("resolved OCI images missing blob storage reference: %v", names)
	}
}

func TestOfflineSource_ResolvesHostPackagesRootDir(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"bin/zonctl-real":                                   "fake zonctl binary",
		"bin/helm":                                          "fake helm binary",
		"bin/appliance-host-agentd":                         "fake appliance host agent daemon",
		"k3s/binary/k3s":                                    "fake k3s binary",
		"charts/appliance-chart-2.4.0.tgz":                  "fake appliance chart",
		"configuration/values.yaml":                         "replicaCount: 1\n",
		"oci-images/appliance-host-agent.tar":               "fake appliance host agent image",
		"oci-images/blob-storage.tar":                       "fake blob storage image",
		"host-packages/ubuntu/24.04/amd64/avahi-daemon.deb": "fake avahi deb",
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
		case rel == "bin/zonctl-real", rel == "bin/helm", rel == "bin/appliance-host-agentd":
			component = "appliance"
		case rel == "k3s/binary/k3s":
			component = "k3s-binary"
		case rel == "charts/appliance-chart-2.4.0.tgz":
			component = "chart"
		case strings.HasPrefix(rel, "oci-images/"):
			component = "oci-images"
		case strings.HasPrefix(rel, "host-packages/"):
			component = "host-packages"
		case strings.HasPrefix(rel, "artifacts/"):
			component = "artifacts"
		}
		entry := map[string]any{
			"path": rel, "component": component, "digest": digest, "sizeBytes": len(content),
		}
		if imageReference := sourceFixtureImageReference(rel); imageReference != "" {
			entry["imageReference"] = imageReference
		}
		manifestEntries = append(manifestEntries, entry)
	}
	appendTestMetadataBundleManifestEntry(t, dir, &manifestEntries)

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
	resolved, _, err := source.Resolve(context.Background(), "storage")
	if err != nil {
		t.Fatalf("expected bundle to resolve, got: %v", err)
	}
	want := filepath.Join(dir, "host-packages")
	if resolved.HostPackagesRootDir != want {
		t.Fatalf("HostPackagesRootDir = %q, want %q", resolved.HostPackagesRootDir, want)
	}
}

func TestOfflineSource_RequiresHostPackages(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"bin/zonctl-real":                     "fake zonctl binary",
		"bin/helm":                            "fake helm binary",
		"bin/appliance-host-agentd":           "fake appliance host agent daemon",
		"k3s/binary/k3s":                      "fake k3s binary",
		"charts/appliance-chart-2.4.0.tgz":    "fake appliance chart",
		"configuration/values.yaml":           "replicaCount: 1\n",
		"oci-images/appliance-host-agent.tar": "fake appliance host agent image",
		"oci-images/blob-storage.tar":         "fake blob storage image",
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
		case rel == "bin/zonctl-real", rel == "bin/helm", rel == "bin/appliance-host-agentd":
			component = "appliance"
		case rel == "k3s/binary/k3s":
			component = "k3s-binary"
		case rel == "charts/appliance-chart-2.4.0.tgz":
			component = "chart"
		case strings.HasPrefix(rel, "artifacts/"):
			component = "artifacts"
		case strings.HasPrefix(rel, "oci-images/"):
			component = "oci-images"
		}
		entry := map[string]any{
			"path": rel, "component": component, "digest": digest, "sizeBytes": len(content),
		}
		if imageReference := sourceFixtureImageReference(rel); imageReference != "" {
			entry["imageReference"] = imageReference
		}
		manifestEntries = append(manifestEntries, entry)
	}
	appendTestMetadataBundleManifestEntry(t, dir, &manifestEntries)

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
	_, _, err = source.Resolve(context.Background(), "storage-landns")
	if err == nil {
		t.Fatal("expected resolve to reject bundle without host-packages")
	}
	if !strings.Contains(err.Error(), "host-packages") {
		t.Fatalf("expected host-packages error, got: %v", err)
	}
}
