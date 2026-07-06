package verify_test

import (
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

func sampleStatement() verify.ProvenanceStatement {
	return verify.ProvenanceStatement{
		BuilderID: "https://appliance-code.internal/builders/release-ci",
		Subjects: []verify.ProvenanceSubject{
			{Name: "control-plane-image", Digest: map[string]string{"sha256": "abc123"}},
		},
	}
}

func TestVerifyProvenance_Valid(t *testing.T) {
	stmt := sampleStatement()
	err := verify.VerifyProvenance(stmt, []string{"https://appliance-code.internal/builders/release-ci"}, "control-plane-image", "sha256:abc123")
	if err != nil {
		t.Errorf("expected valid provenance to verify, got: %v", err)
	}
}

// Wrong identity: the statement was produced by a builder that is not on
// the allowlist.
func TestVerifyProvenance_WrongBuilderIdentity(t *testing.T) {
	stmt := sampleStatement()
	err := verify.VerifyProvenance(stmt, []string{"https://some-other-builder/ci"}, "control-plane-image", "sha256:abc123")
	if err == nil {
		t.Error("expected untrusted builder identity to fail verification")
	}
}

// Missing evidence: no subject in the statement matches the artifact
// being verified.
func TestVerifyProvenance_MissingSubject(t *testing.T) {
	stmt := sampleStatement()
	err := verify.VerifyProvenance(stmt, []string{"https://appliance-code.internal/builders/release-ci"}, "argo-crds", "sha256:abc123")
	if err == nil {
		t.Error("expected missing subject to fail verification")
	}
}

// Tamper: the artifact's actual digest no longer matches what the
// provenance statement attests to.
func TestVerifyProvenance_DigestMismatch(t *testing.T) {
	stmt := sampleStatement()
	err := verify.VerifyProvenance(stmt, []string{"https://appliance-code.internal/builders/release-ci"}, "control-plane-image", "sha256:tampereddigest")
	if err == nil {
		t.Error("expected mismatched subject digest to fail verification")
	}
}
