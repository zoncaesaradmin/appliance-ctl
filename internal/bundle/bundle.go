// Package bundle loads and verifies a complete air-gap release bundle:
// the signed release-manifest.json plus every bundle-local artifact it
// describes. "The appliance command... reads only bundle-local artifacts
// listed in the signed release manifest, verifies them before privileged
// changes... A missing artifact is a hard integrity failure; there is no
// remote fallback." (docs/release-plan.md)
package bundle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/manifest"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

// Entry is one manifest-described artifact, with Path resolved to an
// absolute path under the bundle root.
type Entry struct {
	Path       string // absolute path on disk
	Component  string
	Digest     string
	SizeBytes  int64
	Executable bool
	// ImageReference is set for k3s-images/oci-images entries: the OCI
	// image reference this archive contains, used to detect whether it
	// is already imported into the K3s image store.
	ImageReference string
}

// Compatibility mirrors release-manifest.v1's compatibility block.
type Compatibility struct {
	K3sVersion   string
	ChartVersion string
	// SupportedUpgradeSources lists appliance versions this release may
	// upgrade from (the N-1 policy).
	SupportedUpgradeSources []string
}

// Bundle is a verified, loaded air-gap release bundle. Every Entries()
// path is guaranteed to exist under RootDir with a digest and size that
// matched the signed manifest at load time.
type Bundle struct {
	RootDir       string
	BundleVersion string
	ReleaseID     string
	Compatibility Compatibility
	entries       []Entry
}

type manifestDoc struct {
	SchemaVersion int    `json:"schemaVersion"`
	BundleVersion string `json:"bundleVersion"`
	ReleaseID     string `json:"releaseId"`
	Compatibility struct {
		K3sVersion              string   `json:"k3sVersion"`
		ChartVersion            string   `json:"chartVersion"`
		SupportedUpgradeSources []string `json:"supportedUpgradeSources"`
	} `json:"compatibility"`
	SigningKeyID string `json:"signingKeyId"`
	Entries      []struct {
		Path           string `json:"path"`
		Component      string `json:"component"`
		Digest         string `json:"digest"`
		SizeBytes      int64  `json:"sizeBytes"`
		Executable     bool   `json:"executable"`
		ImageReference string `json:"imageReference"`
	} `json:"entries"`
}

// Load reads rootDir/release-manifest.json, checks it against
// schemas/release-manifest.v1.schema.json, verifies its detached
// signature (rootDir/release-manifest.sig) against pub, and then
// verifies every entry's digest and size. It fails closed: any missing
// file, digest mismatch, or bad signature is an error, and Load never
// reads or writes anything outside rootDir.
func Load(rootDir string, pub *verify.PublicKey) (*Bundle, []evidence.Check, error) {
	manifestPath := filepath.Join(rootDir, "release-manifest.json")
	sigPath := filepath.Join(rootDir, "release-manifest.sig")

	var checks []evidence.Check

	sigCheck, err := verifyManifestSignature(manifestPath, sigPath, pub)
	checks = append(checks, sigCheck)
	if err != nil {
		return nil, checks, err
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, checks, fmt.Errorf("bundle: read %s: %w", manifestPath, err)
	}

	if err := manifest.Validate(manifest.KindReleaseManifest, data); err != nil {
		return nil, checks, fmt.Errorf("bundle: %s does not satisfy release-manifest.v1: %w", manifestPath, err)
	}

	var doc manifestDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, checks, fmt.Errorf("bundle: parse %s: %w", manifestPath, err)
	}

	b := &Bundle{
		RootDir:       rootDir,
		BundleVersion: doc.BundleVersion,
		ReleaseID:     doc.ReleaseID,
		Compatibility: Compatibility{
			K3sVersion:              doc.Compatibility.K3sVersion,
			ChartVersion:            doc.Compatibility.ChartVersion,
			SupportedUpgradeSources: doc.Compatibility.SupportedUpgradeSources,
		},
	}

	var artifacts []verify.Artifact
	for _, e := range doc.Entries {
		absPath := filepath.Join(rootDir, e.Path)
		b.entries = append(b.entries, Entry{
			Path:           absPath,
			Component:      e.Component,
			Digest:         e.Digest,
			SizeBytes:      e.SizeBytes,
			Executable:     e.Executable,
			ImageReference: e.ImageReference,
		})
		artifacts = append(artifacts, verify.Artifact{
			Name:              e.Path,
			Path:              absPath,
			ExpectedDigest:    e.Digest,
			ExpectedSizeBytes: e.SizeBytes,
		})
	}

	entryChecks, err := verify.VerifyArtifacts(nil, artifacts)
	checks = append(checks, entryChecks...)
	if err != nil {
		return nil, checks, fmt.Errorf("bundle: %w", err)
	}

	return b, checks, nil
}

func verifyManifestSignature(manifestPath, sigPath string, pub *verify.PublicKey) (evidence.Check, error) {
	check := evidence.Check{
		ID:              "release-manifest-signature",
		Category:        "security",
		Idempotent:      true,
		SecretsRedacted: true,
	}
	if pub == nil {
		check.Status = evidence.StatusFail
		check.Message = "no verification key supplied for the release manifest"
		return check, fmt.Errorf("bundle: no public key supplied to verify %s", manifestPath)
	}
	if err := verify.VerifyFileSignature(*pub, manifestPath, sigPath); err != nil {
		check.Status = evidence.StatusFail
		check.Message = err.Error()
		return check, fmt.Errorf("bundle: %w", err)
	}
	check.Status = evidence.StatusPass
	check.Message = fmt.Sprintf("release manifest signature verifies against key %q", pub.ID)
	return check, nil
}

// Entries returns every manifest entry belonging to component, in
// manifest order.
func (b *Bundle) Entries(component string) []Entry {
	var out []Entry
	for _, e := range b.entries {
		if e.Component == component {
			out = append(out, e)
		}
	}
	return out
}

// Path returns the single entry's resolved path for a component that has
// exactly one entry (e.g. "appliance", "k3s-binary"). ok is false if
// there is not exactly one matching entry.
func (b *Bundle) Path(component string) (path string, ok bool) {
	entries := b.Entries(component)
	if len(entries) != 1 {
		return "", false
	}
	return entries[0].Path, true
}
