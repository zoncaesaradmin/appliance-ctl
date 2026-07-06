package bundle_test

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/bundle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

// buildBundle writes a minimal, internally-consistent bundle directory:
// one entry file, a release-manifest.json describing it, and a valid
// detached signature over the manifest bytes.
func buildBundle(t *testing.T) (dir string, pub verify.PublicKey) {
	t.Helper()
	dir = t.TempDir()

	entryContent := []byte("fake appliance chart bytes")
	entryPath := "charts/appliance-chart-2.4.0.tgz"
	if err := os.MkdirAll(filepath.Join(dir, "charts"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, entryPath), entryContent, 0o640); err != nil {
		t.Fatal(err)
	}
	digest, err := verify.Digest(filepath.Join(dir, entryPath))
	if err != nil {
		t.Fatal(err)
	}

	doc := map[string]any{
		"schemaVersion": 1,
		"bundleVersion": "2.4.0",
		"releaseId":     "01J8QK3F9G7XA6P0V6ZC9N6R4T",
		"hostBaseline":  map[string]any{"os": "ubuntu", "osVersion": "24.04", "arch": "amd64"},
		"builtAt":       "2026-07-04T00:00:00Z",
		"compatibility": map[string]any{"k3sVersion": "v1.30.4+k3s1", "chartVersion": "2.4.0", "argoVersion": "3.5.2"},
		"signingKeyId":  "release-signing-key",
		"entries": []map[string]any{
			{"path": entryPath, "component": "chart", "digest": digest, "sizeBytes": len(entryContent)},
		},
	}
	manifestBytes, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "release-manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o640); err != nil {
		t.Fatal(err)
	}

	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(privKey, manifestBytes)
	if err := os.WriteFile(filepath.Join(dir, "release-manifest.sig"), sig, 0o640); err != nil {
		t.Fatal(err)
	}

	return dir, verify.PublicKey{ID: "release-signing-key", Key: pubKey}
}

func TestLoad_ValidBundle(t *testing.T) {
	dir, pub := buildBundle(t)

	b, checks, err := bundle.Load(dir, &pub)
	if err != nil {
		t.Fatalf("expected a consistent bundle to load, got: %v", err)
	}
	if b.BundleVersion != "2.4.0" {
		t.Errorf("expected bundle version 2.4.0, got %s", b.BundleVersion)
	}
	if len(checks) == 0 {
		t.Error("expected at least one evidence check")
	}

	path, ok := b.Path("chart")
	if !ok {
		t.Fatal("expected exactly one chart entry")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected resolved chart path to exist: %v", err)
	}
}

// Tamper: a bundle file that no longer matches its manifest digest.
func TestLoad_TamperedEntryFailsClosed(t *testing.T) {
	dir, pub := buildBundle(t)

	if err := os.WriteFile(filepath.Join(dir, "charts", "appliance-chart-2.4.0.tgz"), []byte("tampered!!"), 0o640); err != nil {
		t.Fatal(err)
	}

	if _, _, err := bundle.Load(dir, &pub); err == nil {
		t.Error("expected a tampered entry to fail verification")
	}
}

// Wrong identity: the manifest is signed by a key other than the one the
// caller trusts.
func TestLoad_WrongSigningKeyFailsClosed(t *testing.T) {
	dir, _ := buildBundle(t)

	attackerPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	untrusted := verify.PublicKey{ID: "untrusted", Key: attackerPub}

	if _, _, err := bundle.Load(dir, &untrusted); err == nil {
		t.Error("expected an unpinned signing key to fail verification")
	}
}

// Missing evidence: an entry the manifest describes was never delivered.
func TestLoad_MissingEntryFailsClosed(t *testing.T) {
	dir, pub := buildBundle(t)

	if err := os.Remove(filepath.Join(dir, "charts", "appliance-chart-2.4.0.tgz")); err != nil {
		t.Fatal(err)
	}

	if _, _, err := bundle.Load(dir, &pub); err == nil {
		t.Error("expected a missing entry to fail verification")
	}
}

func TestLoad_NoPublicKeyFailsClosed(t *testing.T) {
	dir, _ := buildBundle(t)

	if _, _, err := bundle.Load(dir, nil); err == nil {
		t.Error("expected a nil public key to fail verification rather than skip it")
	}
}
