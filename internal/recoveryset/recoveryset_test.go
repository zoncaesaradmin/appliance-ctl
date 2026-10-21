package recoveryset

import (
	"testing"
	"time"
)

func TestManifestRejectsLiveDirectorySemantics(t *testing.T) {
	m := Manifest{Format: Format, ID: "set-1", CreatedAt: time.Now(), Database: DatabaseArtifact{Engine: "postgres", Format: "custom", Path: "database.dump", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	m.Database.Format = "pgdata"
	if err := m.Validate(); err == nil {
		t.Fatal("expected live PGDATA format to be rejected")
	}
	m.Database.Format, m.Database.SHA256 = "custom", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	if err := m.Validate(); err == nil {
		t.Fatal("expected non-hex checksum to be rejected")
	}
}
