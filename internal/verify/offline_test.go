package verify_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

// TestVerify_RequiresNoNetworkAccess is a regression guard for "Installation
// is tested with public egress denied and has no remote fallback
// endpoints" (docs/release-plan.md, Security And Supply Chain): it points
// the process-wide default DNS resolver at a dialer that always errors,
// then runs a full digest/size/signature/provenance/vulnerability
// verification cycle. If any verify code path ever tried to resolve a
// host or open a connection, this test would fail even though every input
// here is a local file or in-memory value.
func TestVerify_RequiresNoNetworkAccess(t *testing.T) {
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("network access is not permitted in this test")
		},
	}
	t.Cleanup(func() { net.DefaultResolver = original })

	dir := t.TempDir()
	path := filepath.Join(dir, "chart.tgz")
	if err := os.WriteFile(path, []byte("chart contents"), 0o600); err != nil {
		t.Fatal(err)
	}

	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sigPath := filepath.Join(dir, "chart.tgz.sig")
	if err := os.WriteFile(sigPath, ed25519.Sign(privKey, []byte("chart contents")), 0o600); err != nil {
		t.Fatal(err)
	}
	pub := verify.PublicKey{ID: "release-signing-key", Key: pubKey}

	digest, err := verify.Digest(path)
	if err != nil {
		t.Fatalf("Digest should not require network access: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := verify.VerifyArtifacts(&pub, []verify.Artifact{
		{Name: "appliance-chart", Path: path, ExpectedDigest: digest, ExpectedSizeBytes: info.Size(), SignaturePath: sigPath},
	}); err != nil {
		t.Errorf("VerifyArtifacts should succeed offline: %v", err)
	}

	stmt := sampleStatement()
	if err := verify.VerifyProvenance(stmt, []string{stmt.BuilderID}, "control-plane-image", "sha256:abc123"); err != nil {
		t.Errorf("VerifyProvenance should succeed offline: %v", err)
	}

	findings := []verify.Finding{{ID: "CVE-2026-0099", Package: "libcorge", Severity: verify.SeverityLow}}
	if _, err := verify.EvaluateVulnerabilityPolicy(findings, nil, nil, verify.SeverityHigh, time.Now()); err != nil {
		t.Errorf("EvaluateVulnerabilityPolicy should succeed offline: %v", err)
	}
}
