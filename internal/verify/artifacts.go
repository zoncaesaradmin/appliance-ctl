package verify

import (
	"errors"
	"fmt"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
)

// Artifact describes one file to verify: its expected digest and size,
// and an optional detached signature. It is deliberately generic so the
// same verifier checks both a release-input.json artifact and a
// release-manifest.json entry.
type Artifact struct {
	Name              string // logical name used in check IDs, e.g. "control-plane-image"
	Path              string // resolved path to the file on disk
	ExpectedDigest    string // "sha256:<hex>"
	ExpectedSizeBytes int64
	SignaturePath     string // empty means this artifact carries no detached signature
}

// VerifyArtifacts checks every artifact's digest, size, and (when
// SignaturePath is set) signature against pub. It always returns the full
// set of evidence checks, even when some fail, so a failed verification
// still produces a complete evidence report for the support bundle. err is
// non-nil whenever any check did not pass: this package fails closed.
func VerifyArtifacts(pub *PublicKey, artifacts []Artifact) ([]evidence.Check, error) {
	var checks []evidence.Check
	var failures []error

	for _, a := range artifacts {
		sanitizedName := evidence.SanitizeIDSegment(a.Name)
		now := time.Now()

		digestCheck := evidence.Check{
			ID:              sanitizedName + "-digest",
			Category:        "manifest",
			Timestamp:       now.UTC(),
			Idempotent:      true,
			SecretsRedacted: true,
		}
		if err := VerifyDigest(a.Path, a.ExpectedDigest); err != nil {
			digestCheck.Status = evidence.StatusFail
			digestCheck.Message = err.Error()
			failures = append(failures, fmt.Errorf("%s: %w", a.Name, err))
		} else {
			digestCheck.Status = evidence.StatusPass
			digestCheck.Message = fmt.Sprintf("%s digest matches %s", a.Name, a.ExpectedDigest)
		}
		digestCheck.DurationMs = time.Since(now).Milliseconds()
		checks = append(checks, digestCheck)

		now = time.Now()
		sizeCheck := evidence.Check{
			ID:              sanitizedName + "-size",
			Category:        "manifest",
			Timestamp:       now.UTC(),
			Idempotent:      true,
			SecretsRedacted: true,
		}
		if err := VerifySize(a.Path, a.ExpectedSizeBytes); err != nil {
			sizeCheck.Status = evidence.StatusFail
			sizeCheck.Message = err.Error()
			failures = append(failures, fmt.Errorf("%s: %w", a.Name, err))
		} else {
			sizeCheck.Status = evidence.StatusPass
			sizeCheck.Message = fmt.Sprintf("%s size matches %d bytes", a.Name, a.ExpectedSizeBytes)
		}
		sizeCheck.DurationMs = time.Since(now).Milliseconds()
		checks = append(checks, sizeCheck)

		if a.SignaturePath == "" {
			continue
		}

		now = time.Now()
		sigCheck := evidence.Check{
			ID:              sanitizedName + "-signature",
			Category:        "security",
			Timestamp:       now.UTC(),
			Idempotent:      true,
			SecretsRedacted: true,
		}
		switch {
		case pub == nil:
			sigCheck.Status = evidence.StatusFail
			sigCheck.Message = fmt.Sprintf("%s has a signature but no verification key was supplied", a.Name)
			failures = append(failures, fmt.Errorf("%s: no public key supplied to verify signature", a.Name))
		default:
			if err := VerifyFileSignature(*pub, a.Path, a.SignaturePath); err != nil {
				sigCheck.Status = evidence.StatusFail
				sigCheck.Message = err.Error()
				failures = append(failures, fmt.Errorf("%s: %w", a.Name, err))
			} else {
				sigCheck.Status = evidence.StatusPass
				sigCheck.Message = fmt.Sprintf("%s signature verifies against key %q", a.Name, pub.ID)
			}
		}
		sigCheck.DurationMs = time.Since(now).Milliseconds()
		checks = append(checks, sigCheck)
	}

	if len(failures) > 0 {
		return checks, fmt.Errorf("verify: %d artifact check(s) failed: %w", len(failures), errors.Join(failures...))
	}
	return checks, nil
}
