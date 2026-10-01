package cluster_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cluster"
)

func TestEnrollmentSignatureAndFingerprintValidation(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	nonce, err := cluster.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	e := cluster.Enrollment{ClusterID: "cluster-1", ApplianceName: "zon", ApplianceProfile: "std-llm", ControlPlaneNode: "control-1", NodeRole: "inference", ReleaseID: "release-1", ReleaseVersion: "1.2.3", ControlEndpoint: "https://10.0.0.10:6443", ClusterCAHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExpectedNodeName: "gpu-worker-1", K3sToken: "K10token", TokenFingerprint: cluster.TokenFingerprint("K10token"), IssuedAt: now, ExpiresAt: now.Add(time.Hour), Nonce: nonce}
	if err := e.Sign(private); err != nil {
		t.Fatal(err)
	}
	if err := e.Validate(now, cluster.Fingerprint(public)); err != nil {
		t.Fatalf("valid enrollment rejected: %v", err)
	}
	e.ExpectedNodeName = "tampered"
	if err := e.Validate(now, cluster.Fingerprint(public)); err == nil {
		t.Fatal("tampered enrollment accepted")
	}
}

func TestEnrollmentRejectsUnpinnedSigner(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := cluster.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	e := cluster.Enrollment{ClusterID: "cluster-1", ApplianceName: "zon", ApplianceProfile: "std-llm", ControlPlaneNode: "control-1", NodeRole: "worker", ReleaseID: "release-1", ReleaseVersion: "1.2.3", ControlEndpoint: "https://10.0.0.10:6443", ClusterCAHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExpectedNodeName: "gpu-worker-1", K3sToken: "K10token", TokenFingerprint: cluster.TokenFingerprint("K10token"), IssuedAt: now, ExpiresAt: now.Add(time.Hour), Nonce: nonce}
	if err := e.Sign(private); err != nil {
		t.Fatal(err)
	}
	if err := e.Validate(now, ""); err == nil {
		t.Fatal("un-pinned enrollment accepted")
	}
	if err := e.Validate(now, cluster.Fingerprint(public)); err != nil {
		t.Fatalf("pinned enrollment rejected: %v", err)
	}
}

func TestWriteAndReadEnrollment(t *testing.T) {
	path := t.TempDir() + "/worker.enrollment"
	e := cluster.Enrollment{ClusterID: "cluster-1"}
	if err := cluster.WriteEnrollment(path, e); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("enrollment mode = %o", info.Mode().Perm())
	}
	got, err := cluster.ReadEnrollment(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ClusterID != e.ClusterID {
		t.Fatalf("cluster ID = %q", got.ClusterID)
	}
}

func TestLoadOrCreateSignerIsStableAndPrivate(t *testing.T) {
	path := t.TempDir() + "/cluster-enrollment.key"
	_, first, err := cluster.LoadOrCreateSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o", info.Mode().Perm())
	}
	_, second, err := cluster.LoadOrCreateSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("signer changed: %s != %s", first, second)
	}
}
