package modelpack_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/modelpack"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

func TestLoadAndImport(t *testing.T) {
	root := t.TempDir()
	blobPath := filepath.Join(root, "blobs", "weights.bin")
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o750); err != nil {
		t.Fatal(err)
	}
	content := []byte("fake-qwen-weights")
	if err := os.WriteFile(blobPath, content, 0o640); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	manifest := modelpack.Manifest{
		SchemaVersion: 1,
		Kind:          modelpack.KindV1,
		ModelID:       "qwen2.5-coder:14b",
		Runtime:       "ollama",
		Digest:        digest,
		SizeBytes:     int64(len(content)),
		MinRAMGB:      30,
		Blobs: []modelpack.Blob{{
			Path:      "blobs/weights.bin",
			Digest:    digest,
			SizeBytes: int64(len(content)),
		}},
	}
	manifest.Compatibility.InferenceVersion = "0.6.5"
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, modelpack.ManifestFileName), append(data, '\n'), 0o640); err != nil {
		t.Fatal(err)
	}

	pack, err := modelpack.Load(root, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	destRoot := t.TempDir()
	imported, err := pack.Import(destRoot)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if _, err := os.Stat(filepath.Join(imported, "weights.bin")); err != nil {
		t.Fatalf("imported blob missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(imported, modelpack.ManifestFileName)); err != nil {
		t.Fatalf("imported manifest missing: %v", err)
	}
}

func TestLoadRequiresSignatureWhenKeyProvided(t *testing.T) {
	root := t.TempDir()
	blobPath := filepath.Join(root, "blob.bin")
	content := []byte("x")
	if err := os.WriteFile(blobPath, content, 0o640); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	manifest := modelpack.Manifest{
		SchemaVersion: 1,
		Kind:          modelpack.KindV1,
		ModelID:       "m",
		Runtime:       "ollama",
		SizeBytes:     1,
		Blobs:         []modelpack.Blob{{Path: "blob.bin", Digest: digest, SizeBytes: 1}},
	}
	manifest.Compatibility.InferenceVersion = "0.6.5"
	data, _ := json.Marshal(manifest)
	_ = os.WriteFile(filepath.Join(root, modelpack.ManifestFileName), data, 0o640)

	pub := &verify.PublicKey{ID: "test", Key: ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))}
	if _, err := modelpack.Load(root, pub); err == nil {
		t.Fatal("expected missing signature to fail when public key is supplied")
	}
}
