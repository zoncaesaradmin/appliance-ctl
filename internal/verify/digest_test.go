package verify_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifyDigest_Matches(t *testing.T) {
	path := writeTempFile(t, "release payload v1")

	digest, err := verify.Digest(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := verify.VerifyDigest(path, digest); err != nil {
		t.Errorf("expected matching digest to verify, got: %v", err)
	}
}

// Tamper: content changes after the manifest digest was recorded.
func TestVerifyDigest_Tamper(t *testing.T) {
	path := writeTempFile(t, "release payload v1")

	originalDigest, err := verify.Digest(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte("tampered payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := verify.VerifyDigest(path, originalDigest); err == nil {
		t.Error("expected tampered content to fail digest verification")
	}
}

// Missing evidence: the artifact the manifest describes was never
// delivered.
func TestVerifyDigest_MissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.bin")

	if err := verify.VerifyDigest(missing, "sha256:0000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Error("expected missing file to fail verification")
	}
}

func TestVerifySize_Mismatch(t *testing.T) {
	path := writeTempFile(t, "twenty bytes of data!")

	if err := verify.VerifySize(path, 999); err == nil {
		t.Error("expected size mismatch to fail verification")
	}
	if err := verify.VerifySize(path, int64(len("twenty bytes of data!"))); err != nil {
		t.Errorf("expected matching size to verify, got: %v", err)
	}
}
