package support_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/redact"
	"github.com/zoncaesaradmin/appliance-ctl/internal/support"
)

func TestBuild_ProducesReadableArchive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "support-bundle.tar.gz")
	r := redact.New()

	err := support.Build(path, []support.Source{
		{Name: "installed-state.json", Content: []byte(`{"installedVersion":"2.4.0"}`)},
	}, r)
	if err != nil {
		t.Fatal(err)
	}

	files, err := support.Extract(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["installed-state.json"]; !ok {
		t.Error("expected installed-state.json to be present in the archive")
	}
	if _, ok := files["manifest.json"]; !ok {
		t.Error("expected manifest.json to be present in the archive")
	}
}

// Secret leakage: a secret value that leaked into a source document must
// never appear in cleartext in the archived bundle, even though this
// package has no idea which fields are sensitive — it only knows what
// the Redactor has been told about.
func TestBuild_ScrubsRegisteredSecretFromArchive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "support-bundle.tar.gz")
	r := redact.New()
	r.Register("super-secret-token-123")

	leakedDoc := []byte(`{"debug":"connected using token super-secret-token-123"}`)
	err := support.Build(path, []support.Source{
		{Name: "evidence/install.json", Content: leakedDoc},
	}, r)
	if err != nil {
		t.Fatal(err)
	}

	files, err := support.Extract(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if bytes.Contains(content, []byte("super-secret-token-123")) {
			t.Errorf("secret leaked in cleartext into archive entry %q: %s", name, content)
		}
	}
	if !bytes.Contains(files["evidence/install.json"], []byte(redact.Placeholder)) {
		t.Error("expected the redaction placeholder to appear in place of the secret")
	}
}

func TestBuild_ManifestDigestsReflectRedactedContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "support-bundle.tar.gz")
	r := redact.New()
	r.Register("hunter2")

	err := support.Build(path, []support.Source{
		{Name: "notes.txt", Content: []byte("password hunter2")},
	}, r)
	if err != nil {
		t.Fatal(err)
	}

	files, err := support.Extract(path)
	if err != nil {
		t.Fatal(err)
	}

	var manifest []support.ManifestEntry
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest) != 1 {
		t.Fatalf("expected 1 manifest entry, got %d", len(manifest))
	}
	if manifest[0].SizeBytes != len(files["notes.txt"]) {
		t.Errorf("manifest size %d does not match archived (redacted) content size %d", manifest[0].SizeBytes, len(files["notes.txt"]))
	}
}
