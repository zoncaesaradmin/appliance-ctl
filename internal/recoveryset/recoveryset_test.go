package recoveryset

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveLoadAndVerifyFiles(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"database.dump", "configuration.zonconfig", "installed-state.json"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	db, _ := ChecksumFile(filepath.Join(root, "database.dump"))
	config, _ := ChecksumFile(filepath.Join(root, "configuration.zonconfig"))
	receipt, _ := ChecksumFile(filepath.Join(root, "installed-state.json"))
	m := Manifest{Format: Format, ID: "recovery-test", CreatedAt: time.Now().UTC(), PlatformVersion: "0.1.0", Database: DatabaseArtifact{Engine: "postgres", Format: "custom", Path: "database.dump", SHA256: db}, ConfigurationArchive: "configuration.zonconfig", ConfigurationSHA256: config, Artifacts: []Artifact{{Path: "installed-state.json", SHA256: receipt}}}
	if err := Save(root, m); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyFiles(root, loaded); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "database.dump"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFiles(root, loaded); err == nil {
		t.Fatal("tampered dump accepted")
	}
}

func TestManifestRejectsEscapingPath(t *testing.T) {
	m := Manifest{Format: Format, ID: "recovery-test", CreatedAt: time.Now().UTC(), Database: DatabaseArtifact{Engine: "postgres", Format: "custom", Path: "../database.dump", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	if err := m.Validate(); err == nil {
		t.Fatal("escaping path accepted")
	}
}
