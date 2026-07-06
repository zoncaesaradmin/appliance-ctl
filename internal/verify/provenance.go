package verify

import (
	"encoding/json"
	"fmt"
	"os"
)

// ProvenanceStatement is a minimal SLSA/in-toto-style provenance
// statement: who built the artifact set, and the digest of each subject
// they attest to.
type ProvenanceStatement struct {
	BuilderID string              `json:"builderId"`
	Subjects  []ProvenanceSubject `json:"subjects"`
}

// ProvenanceSubject binds a named artifact to the digest(s) the builder
// attests it produced, keyed by algorithm (e.g. "sha256").
type ProvenanceSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// LoadProvenanceStatement reads and parses a provenance statement from
// path.
func LoadProvenanceStatement(path string) (ProvenanceStatement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ProvenanceStatement{}, fmt.Errorf("verify: read provenance %s: %w", path, err)
	}

	var stmt ProvenanceStatement
	if err := json.Unmarshal(data, &stmt); err != nil {
		return ProvenanceStatement{}, fmt.Errorf("verify: parse provenance %s: %w", path, err)
	}
	return stmt, nil
}

// VerifyProvenance fails closed on three distinct grounds: a builder
// identity outside the allowlist, no subject matching subjectName, or a
// subject digest that does not match the artifact's actual digest
// (meaning the provenance was not issued for this exact byte-for-byte
// artifact).
func VerifyProvenance(stmt ProvenanceStatement, allowedBuilderIDs []string, subjectName, actualDigest string) error {
	allowed := false
	for _, id := range allowedBuilderIDs {
		if id == stmt.BuilderID {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("verify: provenance builder identity %q is not allowlisted", stmt.BuilderID)
	}

	for _, s := range stmt.Subjects {
		if s.Name != subjectName {
			continue
		}
		hexDigest, ok := s.Digest["sha256"]
		if !ok {
			return fmt.Errorf("verify: provenance subject %q has no sha256 digest", subjectName)
		}
		got := "sha256:" + hexDigest
		if got != actualDigest {
			return fmt.Errorf("verify: provenance subject %q digest %s does not match artifact digest %s", subjectName, got, actualDigest)
		}
		return nil
	}

	return fmt.Errorf("verify: provenance statement has no subject named %q", subjectName)
}
