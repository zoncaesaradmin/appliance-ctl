package metadatabundle_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/metadatabundle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/runtimeconfig"
)

func TestSeedHost_ExtractsAndValidatesProfile(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "appliance-metadata-bundle-2.4.0.0.tar.zst")
	if err := metadatabundle.WriteMinimalArchive(archive, "2.4.0.0", "core", "builder"); err != nil {
		t.Fatal(err)
	}
	seeded, err := metadatabundle.SeedHost(archive, filepath.Join(root, "state"), filepath.Join(root, "host"), "core")
	if err != nil {
		t.Fatalf("SeedHost: %v", err)
	}
	if seeded.MetadataVersion != "2.4.0.0" {
		t.Fatalf("MetadataVersion=%q", seeded.MetadataVersion)
	}
	if _, err := os.Stat(filepath.Join(seeded.ExtractedDir, "profiles", "catalog.yaml")); err != nil {
		t.Fatalf("extracted catalog: %v", err)
	}
	if err := metadatabundle.ValidateProfile(seeded.ExtractedDir, "missing"); err == nil {
		t.Fatal("expected missing profile to fail")
	}
}

func TestResolvePackage(t *testing.T) {
	packages := map[string]metadatabundle.PackageDefinition{
		"std-llm-amd64": {Capabilities: []string{"inference"}, Runtime: runtimeconfig.Implementation{InferenceEngine: "ollama", Architecture: "amd64", SupportedModes: []string{"cpu"}}},
	}
	selected, err := metadatabundle.ResolvePackage(packages, "inference", "std-llm-amd64")
	if err != nil || selected.InferenceEngine != "ollama" || selected.Architecture != "amd64" || selected.Package != "std-llm-amd64" {
		t.Fatalf("selection=%+v err=%v", selected, err)
	}
	packages["duplicate-cpu"] = packages["std-llm-amd64"]
	if _, err := metadatabundle.ResolvePackage(packages, "inference", ""); err == nil {
		t.Fatal("ambiguous inference package accepted")
	}
}
