package releaseinput

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/manifest"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

// Input is a verified appliance-code release-input set on disk.
type Input struct {
	RootDir        string
	ProductVersion string
	ReleaseID      string
	Compatibility  Compatibility
	Artifacts      Artifacts
}

type Compatibility struct {
	K3sVersion              string
	ChartVersion            string
	ArgoVersion             string
	SupportedUpgradeSources []string
}

type FileArtifact struct {
	Path      string
	Digest    string
	SizeBytes int64
	Signature string
}

type DirArtifact struct {
	Path           string
	ManifestDigest string
}

type Artifacts struct {
	ControlPlaneImage   FileArtifact
	ApplianceChart      FileArtifact
	ArgoCRDs            FileArtifact
	ConfigurationSchema FileArtifact
	Compatibility       FileArtifact
	Checksums           FileArtifact
	SBOM                DirArtifact
	Provenance          DirArtifact
	Notices             DirArtifact
	Tests               DirArtifact
}

type doc struct {
	ProductVersion string `json:"productVersion"`
	ReleaseID      string `json:"releaseId"`
	Artifacts      struct {
		ControlPlaneImage   fileArtifact `json:"controlPlaneImage"`
		ApplianceChart      fileArtifact `json:"applianceChart"`
		ArgoCRDs            fileArtifact `json:"argoCrds"`
		ConfigurationSchema fileArtifact `json:"configurationSchema"`
		Compatibility       fileArtifact `json:"compatibility"`
		Checksums           fileArtifact `json:"checksums"`
		SBOM                dirArtifact  `json:"sbom"`
		Provenance          dirArtifact  `json:"provenance"`
		Notices             dirArtifact  `json:"notices"`
		Tests               dirArtifact  `json:"tests"`
	} `json:"artifacts"`
	Compatibility Compatibility `json:"compatibility"`
}

type fileArtifact struct {
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	SizeBytes int64  `json:"sizeBytes"`
	Signature string `json:"signature"`
}

type dirArtifact struct {
	Path           string `json:"path"`
	ManifestDigest string `json:"manifestDigest"`
}

// Load reads and verifies a release-input directory. It validates
// release-input.json, checks every file artifact's digest and size, and
// verifies each artifact-directory manifest digest using this repo's
// deterministic directory manifest convention.
func Load(rootDir string) (*Input, []evidence.Check, error) {
	data, err := os.ReadFile(filepath.Join(rootDir, "release-input.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("release-input: read release-input.json: %w", err)
	}
	if err := manifest.Validate(manifest.KindReleaseInput, data); err != nil {
		return nil, nil, fmt.Errorf("release-input: release-input.json does not satisfy release-input.v1: %w", err)
	}

	var parsed doc
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, nil, fmt.Errorf("release-input: parse release-input.json: %w", err)
	}

	input := &Input{
		RootDir:        rootDir,
		ProductVersion: parsed.ProductVersion,
		ReleaseID:      parsed.ReleaseID,
		Compatibility:  parsed.Compatibility,
		Artifacts: Artifacts{
			ControlPlaneImage:   toFileArtifact(rootDir, parsed.Artifacts.ControlPlaneImage),
			ApplianceChart:      toFileArtifact(rootDir, parsed.Artifacts.ApplianceChart),
			ArgoCRDs:            toFileArtifact(rootDir, parsed.Artifacts.ArgoCRDs),
			ConfigurationSchema: toFileArtifact(rootDir, parsed.Artifacts.ConfigurationSchema),
			Compatibility:       toFileArtifact(rootDir, parsed.Artifacts.Compatibility),
			Checksums:           toFileArtifact(rootDir, parsed.Artifacts.Checksums),
			SBOM:                toDirArtifact(rootDir, parsed.Artifacts.SBOM),
			Provenance:          toDirArtifact(rootDir, parsed.Artifacts.Provenance),
			Notices:             toDirArtifact(rootDir, parsed.Artifacts.Notices),
			Tests:               toDirArtifact(rootDir, parsed.Artifacts.Tests),
		},
	}

	artifacts := []verify.Artifact{
		{Name: "control-plane-image", Path: input.Artifacts.ControlPlaneImage.Path, ExpectedDigest: input.Artifacts.ControlPlaneImage.Digest, ExpectedSizeBytes: input.Artifacts.ControlPlaneImage.SizeBytes},
		{Name: "appliance-chart", Path: input.Artifacts.ApplianceChart.Path, ExpectedDigest: input.Artifacts.ApplianceChart.Digest, ExpectedSizeBytes: input.Artifacts.ApplianceChart.SizeBytes},
		{Name: "argo-crds", Path: input.Artifacts.ArgoCRDs.Path, ExpectedDigest: input.Artifacts.ArgoCRDs.Digest, ExpectedSizeBytes: input.Artifacts.ArgoCRDs.SizeBytes},
		{Name: "configuration-schema", Path: input.Artifacts.ConfigurationSchema.Path, ExpectedDigest: input.Artifacts.ConfigurationSchema.Digest, ExpectedSizeBytes: input.Artifacts.ConfigurationSchema.SizeBytes},
		{Name: "compatibility", Path: input.Artifacts.Compatibility.Path, ExpectedDigest: input.Artifacts.Compatibility.Digest, ExpectedSizeBytes: input.Artifacts.Compatibility.SizeBytes},
		{Name: "checksums", Path: input.Artifacts.Checksums.Path, ExpectedDigest: input.Artifacts.Checksums.Digest, ExpectedSizeBytes: input.Artifacts.Checksums.SizeBytes},
	}
	checks, err := verify.VerifyArtifacts(nil, artifacts)
	if err != nil {
		return nil, checks, fmt.Errorf("release-input: %w", err)
	}

	dirChecks, err := verifyDirArtifacts([]namedDirArtifact{
		{Name: "sbom", DirArtifact: input.Artifacts.SBOM},
		{Name: "provenance", DirArtifact: input.Artifacts.Provenance},
		{Name: "notices", DirArtifact: input.Artifacts.Notices},
		{Name: "tests", DirArtifact: input.Artifacts.Tests},
	})
	checks = append(checks, dirChecks...)
	if err != nil {
		return nil, checks, fmt.Errorf("release-input: %w", err)
	}

	return input, checks, nil
}

type namedDirArtifact struct {
	Name string
	DirArtifact
}

func verifyDirArtifacts(artifacts []namedDirArtifact) ([]evidence.Check, error) {
	var checks []evidence.Check
	var failures []error
	for _, artifact := range artifacts {
		now := time.Now().UTC()
		check := evidence.Check{
			ID:              artifact.Name + "-manifest",
			Category:        "manifest",
			Timestamp:       now,
			Idempotent:      true,
			SecretsRedacted: true,
		}
		actual, err := DirectoryManifestDigest(artifact.Path)
		if err != nil {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			failures = append(failures, fmt.Errorf("%s: %w", artifact.Name, err))
		} else if actual != artifact.ManifestDigest {
			check.Status = evidence.StatusFail
			check.Message = fmt.Sprintf("verify: directory manifest digest mismatch for %s: expected %s, got %s", artifact.Path, artifact.ManifestDigest, actual)
			failures = append(failures, fmt.Errorf("%s: digest mismatch", artifact.Name))
		} else {
			check.Status = evidence.StatusPass
			check.Message = fmt.Sprintf("%s directory manifest matches %s", artifact.Name, artifact.ManifestDigest)
		}
		check.DurationMs = time.Since(now).Milliseconds()
		checks = append(checks, check)
	}
	if len(failures) > 0 {
		return checks, fmt.Errorf("verify: %d release-input directory check(s) failed: %w", len(failures), errors.Join(failures...))
	}
	return checks, nil
}

func DirectoryManifestDigest(root string) (string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return "", fmt.Errorf("verify: stat %s: %w", root, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("verify: %s is not a directory", root)
	}

	type entry struct {
		rel  string
		line string
	}
	var entries []entry
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		digest, err := verify.Digest(path)
		if err != nil {
			return err
		}
		entries = append(entries, entry{
			rel:  rel,
			line: fmt.Sprintf("%s\t%s\t%d\n", rel, digest, info.Size()),
		})
		return nil
	}); err != nil {
		return "", fmt.Errorf("verify: walk %s: %w", root, err)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	var manifest bytes.Buffer
	for _, e := range entries {
		manifest.WriteString(e.line)
	}
	sum := sha256.Sum256(manifest.Bytes())
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func toFileArtifact(rootDir string, artifact fileArtifact) FileArtifact {
	return FileArtifact{
		Path:      filepath.Join(rootDir, artifact.Path),
		Digest:    artifact.Digest,
		SizeBytes: artifact.SizeBytes,
		Signature: strings.TrimSpace(artifact.Signature),
	}
}

func toDirArtifact(rootDir string, artifact dirArtifact) DirArtifact {
	return DirArtifact{
		Path:           filepath.Join(rootDir, artifact.Path),
		ManifestDigest: artifact.ManifestDigest,
	}
}
