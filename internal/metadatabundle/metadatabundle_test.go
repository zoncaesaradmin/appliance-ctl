package metadatabundle_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/metadatabundle"
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
