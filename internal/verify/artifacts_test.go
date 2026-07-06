package verify_test

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

func setupSignedArtifact(t *testing.T, content string) (path, sigPath string, pub verify.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "chart.tgz")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub = verify.PublicKey{ID: "release-signing-key", Key: pubKey}

	sigPath = filepath.Join(dir, "chart.tgz.sig")
	sig := ed25519.Sign(privKey, []byte(content))
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
		t.Fatal(err)
	}

	return path, sigPath, pub, privKey
}

func TestVerifyArtifacts_AllPass(t *testing.T) {
	path, sigPath, pub, _ := setupSignedArtifact(t, "chart contents")
	digest, err := verify.Digest(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	checks, err := verify.VerifyArtifacts(&pub, []verify.Artifact{
		{Name: "appliance-chart", Path: path, ExpectedDigest: digest, ExpectedSizeBytes: info.Size(), SignaturePath: sigPath},
	})
	if err != nil {
		t.Fatalf("expected all checks to pass, got: %v", err)
	}
	if len(checks) != 3 {
		t.Fatalf("expected 3 checks (digest, size, signature), got %d", len(checks))
	}
	for _, c := range checks {
		if c.Status != evidence.StatusPass {
			t.Errorf("check %q: expected pass, got %s: %s", c.ID, c.Status, c.Message)
		}
	}

	// The checks returned must themselves compose into a valid evidence.v1
	// report, since that is what a real verify command would persist.
	if _, err := evidence.BuildReport("verify", "2.4.0", "evidence-verify-001", checks, time.Now()); err != nil {
		t.Errorf("expected checks to build a valid evidence report, got: %v", err)
	}
}

// Tamper: file contents changed after the manifest digest was pinned.
func TestVerifyArtifacts_TamperFailsClosed(t *testing.T) {
	path, sigPath, pub, _ := setupSignedArtifact(t, "chart contents")
	digest, err := verify.Digest(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte("tampered chart contents!!"), 0o600); err != nil {
		t.Fatal(err)
	}

	checks, err := verify.VerifyArtifacts(&pub, []verify.Artifact{
		{Name: "appliance-chart", Path: path, ExpectedDigest: digest, ExpectedSizeBytes: info.Size(), SignaturePath: sigPath},
	})
	if err == nil {
		t.Fatal("expected tampered artifact to fail verification")
	}
	if got := statusOfCheck(t, checks, "appliance-chart-digest"); got != evidence.StatusFail {
		t.Errorf("expected digest check to fail, got %s", got)
	}
}

// Missing evidence: the manifest references an artifact that was never
// delivered in the bundle.
func TestVerifyArtifacts_MissingArtifactFailsClosed(t *testing.T) {
	pub := verify.PublicKey{ID: "release-signing-key"}
	missing := filepath.Join(t.TempDir(), "never-delivered.tgz")

	checks, err := verify.VerifyArtifacts(&pub, []verify.Artifact{
		{Name: "argo-crds", Path: missing, ExpectedDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000", ExpectedSizeBytes: 100},
	})
	if err == nil {
		t.Fatal("expected missing artifact to fail verification")
	}
	if got := statusOfCheck(t, checks, "argo-crds-digest"); got != evidence.StatusFail {
		t.Errorf("expected digest check to fail for missing artifact, got %s", got)
	}
}

// Wrong identity: signed by a key other than the one pinned for
// verification.
func TestVerifyArtifacts_WrongSignerFailsClosed(t *testing.T) {
	path, _, _, _ := setupSignedArtifact(t, "chart contents")
	digest, err := verify.Digest(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	attackerPub, attackerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = attackerPub
	sigPath := filepath.Join(filepath.Dir(path), "chart.tgz.attacker.sig")
	if err := os.WriteFile(sigPath, ed25519.Sign(attackerPriv, []byte("chart contents")), 0o600); err != nil {
		t.Fatal(err)
	}

	pinnedPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := verify.PublicKey{ID: "release-signing-key", Key: pinnedPub}

	checks, err := verify.VerifyArtifacts(&pub, []verify.Artifact{
		{Name: "appliance-chart", Path: path, ExpectedDigest: digest, ExpectedSizeBytes: info.Size(), SignaturePath: sigPath},
	})
	if err == nil {
		t.Fatal("expected signature from an unpinned key to fail verification")
	}
	if got := statusOfCheck(t, checks, "appliance-chart-signature"); got != evidence.StatusFail {
		t.Errorf("expected signature check to fail, got %s", got)
	}
}

func statusOfCheck(t *testing.T, checks []evidence.Check, id string) evidence.Status {
	t.Helper()
	for _, c := range checks {
		if c.ID == id {
			return c.Status
		}
	}
	t.Fatalf("no check with id %q found", id)
	return ""
}
