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
	RootDir       string
	CodeVersion   string
	ReleaseID     string
	Compatibility Compatibility
	Artifacts     Artifacts
}

type Compatibility struct {
	K3sVersion              string
	ChartVersion            string
	WorkflowsVersion        string
	ArtifactServerVersion   string
	DnsVersion              string
	InferenceVersion        string
	SupportedUpgradeSources []string
}

type FileArtifact struct {
	Path           string
	Digest         string
	SizeBytes      int64
	Signature      string
	ImageReference string
}

type DirArtifact struct {
	Path           string
	ManifestDigest string
}

type Artifacts struct {
	ControlPlaneImage       FileArtifact
	UIImage                 FileArtifact
	HostAgentImage          FileArtifact
	HostAgentBinary         FileArtifact
	HostPackages            DirArtifact
	ApplianceChart          FileArtifact
	ArtifactServerImage     FileArtifact
	ArtifactServerChart     FileArtifact
	DnsImage                FileArtifact
	DnsChart                FileArtifact
	BlobStorageImage        FileArtifact
	InferenceRuntimeImage   FileArtifact
	InferenceChart          FileArtifact
	MetadataBundle          FileArtifact
	MessageBrokerImage      FileArtifact
	MessageBrokerChart      FileArtifact
	WorkflowsChart          FileArtifact
	WorkflowControllerImage FileArtifact
	WorkflowExecutorImage   FileArtifact
	ExtraOCIImages          []FileArtifact
	ConfigurationSchema     FileArtifact
	Compatibility           FileArtifact
	Checksums               FileArtifact
	WorkflowsCRDs           DirArtifact
	SBOM                    DirArtifact
	Provenance              DirArtifact
	Notices                 DirArtifact
	Tests                   DirArtifact
}

type doc struct {
	CodeVersion string `json:"codeVersion"`
	ReleaseID   string `json:"releaseId"`
	Artifacts   struct {
		ControlPlaneImage       fileArtifact   `json:"controlPlaneImage"`
		UIImage                 fileArtifact   `json:"uiImage"`
		HostAgentImage          fileArtifact   `json:"hostAgentImage"`
		HostAgentBinary         fileArtifact   `json:"hostAgentBinary"`
		HostPackages            dirArtifact    `json:"hostPackages"`
		ApplianceChart          fileArtifact   `json:"applianceChart"`
		ArtifactServerImage     fileArtifact   `json:"artifactServerImage"`
		ArtifactServerChart     fileArtifact   `json:"artifactServerChart"`
		DnsImage                fileArtifact   `json:"dnsImage"`
		DnsChart                fileArtifact   `json:"dnsChart"`
		BlobStorageImage        fileArtifact   `json:"blobStorageImage"`
		InferenceRuntimeImage   fileArtifact   `json:"inferenceRuntimeImage"`
		InferenceChart          fileArtifact   `json:"inferenceChart"`
		MetadataBundle          fileArtifact   `json:"metadataBundle"`
		MessageBrokerImage      fileArtifact   `json:"messageBrokerImage"`
		MessageBrokerChart      fileArtifact   `json:"messageBrokerChart"`
		WorkflowsChart          fileArtifact   `json:"workflowsChart"`
		WorkflowControllerImage fileArtifact   `json:"workflowControllerImage"`
		WorkflowExecutorImage   fileArtifact   `json:"workflowExecutorImage"`
		ExtraOCIImages          []fileArtifact `json:"extraOCIImages"`
		ConfigurationSchema     fileArtifact   `json:"configurationSchema"`
		Compatibility           fileArtifact   `json:"compatibility"`
		Checksums               fileArtifact   `json:"checksums"`
		WorkflowsCRDs           dirArtifact    `json:"workflowsCRDs"`
		SBOM                    dirArtifact    `json:"sbom"`
		Provenance              dirArtifact    `json:"provenance"`
		Notices                 dirArtifact    `json:"notices"`
		Tests                   dirArtifact    `json:"tests"`
	} `json:"artifacts"`
	Compatibility Compatibility `json:"compatibility"`
}

type fileArtifact struct {
	Path           string `json:"path"`
	Digest         string `json:"digest"`
	SizeBytes      int64  `json:"sizeBytes"`
	Signature      string `json:"signature"`
	ImageReference string `json:"imageReference"`
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
		RootDir:       rootDir,
		CodeVersion:   parsed.CodeVersion,
		ReleaseID:     parsed.ReleaseID,
		Compatibility: parsed.Compatibility,
		Artifacts: Artifacts{
			ControlPlaneImage:       toFileArtifact(rootDir, parsed.Artifacts.ControlPlaneImage),
			UIImage:                 toFileArtifact(rootDir, parsed.Artifacts.UIImage),
			HostAgentImage:          toFileArtifact(rootDir, parsed.Artifacts.HostAgentImage),
			HostAgentBinary:         toFileArtifact(rootDir, parsed.Artifacts.HostAgentBinary),
			HostPackages:            toDirArtifact(rootDir, parsed.Artifacts.HostPackages),
			ApplianceChart:          toFileArtifact(rootDir, parsed.Artifacts.ApplianceChart),
			ArtifactServerImage:     toFileArtifact(rootDir, parsed.Artifacts.ArtifactServerImage),
			ArtifactServerChart:     toFileArtifact(rootDir, parsed.Artifacts.ArtifactServerChart),
			DnsImage:                toFileArtifact(rootDir, parsed.Artifacts.DnsImage),
			DnsChart:                toFileArtifact(rootDir, parsed.Artifacts.DnsChart),
			BlobStorageImage:        toFileArtifact(rootDir, parsed.Artifacts.BlobStorageImage),
			InferenceRuntimeImage:   toFileArtifact(rootDir, parsed.Artifacts.InferenceRuntimeImage),
			InferenceChart:          toFileArtifact(rootDir, parsed.Artifacts.InferenceChart),
			MetadataBundle:          toFileArtifact(rootDir, parsed.Artifacts.MetadataBundle),
			MessageBrokerImage:      toFileArtifact(rootDir, parsed.Artifacts.MessageBrokerImage),
			MessageBrokerChart:      toFileArtifact(rootDir, parsed.Artifacts.MessageBrokerChart),
			WorkflowsChart:          toFileArtifact(rootDir, parsed.Artifacts.WorkflowsChart),
			WorkflowControllerImage: toFileArtifact(rootDir, parsed.Artifacts.WorkflowControllerImage),
			WorkflowExecutorImage:   toFileArtifact(rootDir, parsed.Artifacts.WorkflowExecutorImage),
			ExtraOCIImages:          toFileArtifacts(rootDir, parsed.Artifacts.ExtraOCIImages),
			ConfigurationSchema:     toFileArtifact(rootDir, parsed.Artifacts.ConfigurationSchema),
			Compatibility:           toFileArtifact(rootDir, parsed.Artifacts.Compatibility),
			Checksums:               toFileArtifact(rootDir, parsed.Artifacts.Checksums),
			WorkflowsCRDs:           toDirArtifact(rootDir, parsed.Artifacts.WorkflowsCRDs),
			SBOM:                    toDirArtifact(rootDir, parsed.Artifacts.SBOM),
			Provenance:              toDirArtifact(rootDir, parsed.Artifacts.Provenance),
			Notices:                 toDirArtifact(rootDir, parsed.Artifacts.Notices),
			Tests:                   toDirArtifact(rootDir, parsed.Artifacts.Tests),
		},
	}

	artifacts := []verify.Artifact{
		{Name: "control-plane-image", Path: input.Artifacts.ControlPlaneImage.Path, ExpectedDigest: input.Artifacts.ControlPlaneImage.Digest, ExpectedSizeBytes: input.Artifacts.ControlPlaneImage.SizeBytes},
		{Name: "ui-image", Path: input.Artifacts.UIImage.Path, ExpectedDigest: input.Artifacts.UIImage.Digest, ExpectedSizeBytes: input.Artifacts.UIImage.SizeBytes},
		{Name: "host-agent-image", Path: input.Artifacts.HostAgentImage.Path, ExpectedDigest: input.Artifacts.HostAgentImage.Digest, ExpectedSizeBytes: input.Artifacts.HostAgentImage.SizeBytes},
		{Name: "host-agent-binary", Path: input.Artifacts.HostAgentBinary.Path, ExpectedDigest: input.Artifacts.HostAgentBinary.Digest, ExpectedSizeBytes: input.Artifacts.HostAgentBinary.SizeBytes},
		{Name: "appliance-chart", Path: input.Artifacts.ApplianceChart.Path, ExpectedDigest: input.Artifacts.ApplianceChart.Digest, ExpectedSizeBytes: input.Artifacts.ApplianceChart.SizeBytes},
		{Name: "artifact-server-image", Path: input.Artifacts.ArtifactServerImage.Path, ExpectedDigest: input.Artifacts.ArtifactServerImage.Digest, ExpectedSizeBytes: input.Artifacts.ArtifactServerImage.SizeBytes},
		{Name: "artifact-server-chart", Path: input.Artifacts.ArtifactServerChart.Path, ExpectedDigest: input.Artifacts.ArtifactServerChart.Digest, ExpectedSizeBytes: input.Artifacts.ArtifactServerChart.SizeBytes},
		{Name: "dns-image", Path: input.Artifacts.DnsImage.Path, ExpectedDigest: input.Artifacts.DnsImage.Digest, ExpectedSizeBytes: input.Artifacts.DnsImage.SizeBytes},
		{Name: "dns-chart", Path: input.Artifacts.DnsChart.Path, ExpectedDigest: input.Artifacts.DnsChart.Digest, ExpectedSizeBytes: input.Artifacts.DnsChart.SizeBytes},
		{Name: "blob-storage-image", Path: input.Artifacts.BlobStorageImage.Path, ExpectedDigest: input.Artifacts.BlobStorageImage.Digest, ExpectedSizeBytes: input.Artifacts.BlobStorageImage.SizeBytes},
		{Name: "metadata-bundle", Path: input.Artifacts.MetadataBundle.Path, ExpectedDigest: input.Artifacts.MetadataBundle.Digest, ExpectedSizeBytes: input.Artifacts.MetadataBundle.SizeBytes},
		{Name: "configuration-schema", Path: input.Artifacts.ConfigurationSchema.Path, ExpectedDigest: input.Artifacts.ConfigurationSchema.Digest, ExpectedSizeBytes: input.Artifacts.ConfigurationSchema.SizeBytes},
		{Name: "compatibility", Path: input.Artifacts.Compatibility.Path, ExpectedDigest: input.Artifacts.Compatibility.Digest, ExpectedSizeBytes: input.Artifacts.Compatibility.SizeBytes},
		{Name: "checksums", Path: input.Artifacts.Checksums.Path, ExpectedDigest: input.Artifacts.Checksums.Digest, ExpectedSizeBytes: input.Artifacts.Checksums.SizeBytes},
	}
	if input.Artifacts.MessageBrokerImage.Path != "" {
		artifacts = append(artifacts, verify.Artifact{Name: "message-broker-image", Path: input.Artifacts.MessageBrokerImage.Path, ExpectedDigest: input.Artifacts.MessageBrokerImage.Digest, ExpectedSizeBytes: input.Artifacts.MessageBrokerImage.SizeBytes})
	}
	if input.Artifacts.MessageBrokerChart.Path != "" {
		artifacts = append(artifacts, verify.Artifact{Name: "message-broker-chart", Path: input.Artifacts.MessageBrokerChart.Path, ExpectedDigest: input.Artifacts.MessageBrokerChart.Digest, ExpectedSizeBytes: input.Artifacts.MessageBrokerChart.SizeBytes})
	}
	if input.Artifacts.InferenceRuntimeImage.Path != "" {
		artifacts = append(artifacts, verify.Artifact{
			Name:              "inference-runtime-image",
			Path:              input.Artifacts.InferenceRuntimeImage.Path,
			ExpectedDigest:    input.Artifacts.InferenceRuntimeImage.Digest,
			ExpectedSizeBytes: input.Artifacts.InferenceRuntimeImage.SizeBytes,
		})
	}
	if input.Artifacts.InferenceChart.Path != "" {
		artifacts = append(artifacts, verify.Artifact{
			Name:              "inference-chart",
			Path:              input.Artifacts.InferenceChart.Path,
			ExpectedDigest:    input.Artifacts.InferenceChart.Digest,
			ExpectedSizeBytes: input.Artifacts.InferenceChart.SizeBytes,
		})
	}
	if input.Artifacts.WorkflowsChart.Path != "" {
		artifacts = append(artifacts, verify.Artifact{
			Name:              "workflows-chart",
			Path:              input.Artifacts.WorkflowsChart.Path,
			ExpectedDigest:    input.Artifacts.WorkflowsChart.Digest,
			ExpectedSizeBytes: input.Artifacts.WorkflowsChart.SizeBytes,
		})
	}
	if input.Artifacts.WorkflowControllerImage.Path != "" {
		artifacts = append(artifacts, verify.Artifact{
			Name:              "workflow-controller-image",
			Path:              input.Artifacts.WorkflowControllerImage.Path,
			ExpectedDigest:    input.Artifacts.WorkflowControllerImage.Digest,
			ExpectedSizeBytes: input.Artifacts.WorkflowControllerImage.SizeBytes,
		})
	}
	if input.Artifacts.WorkflowExecutorImage.Path != "" {
		artifacts = append(artifacts, verify.Artifact{
			Name:              "workflow-executor-image",
			Path:              input.Artifacts.WorkflowExecutorImage.Path,
			ExpectedDigest:    input.Artifacts.WorkflowExecutorImage.Digest,
			ExpectedSizeBytes: input.Artifacts.WorkflowExecutorImage.SizeBytes,
		})
	}
	for idx, image := range input.Artifacts.ExtraOCIImages {
		artifacts = append(artifacts, verify.Artifact{
			Name:              fmt.Sprintf("extra-oci-image-%d", idx+1),
			Path:              image.Path,
			ExpectedDigest:    image.Digest,
			ExpectedSizeBytes: image.SizeBytes,
		})
	}
	checks, err := verify.VerifyArtifacts(nil, artifacts)
	if err != nil {
		return nil, checks, fmt.Errorf("release-input: %w", err)
	}

	dirChecks, dirErr := verifyDirArtifacts([]namedDirArtifact{
		{Name: "sbom", DirArtifact: input.Artifacts.SBOM},
		{Name: "provenance", DirArtifact: input.Artifacts.Provenance},
		{Name: "notices", DirArtifact: input.Artifacts.Notices},
		{Name: "tests", DirArtifact: input.Artifacts.Tests},
	})
	if input.Artifacts.HostPackages.Path != "" {
		var hostPackageChecks []evidence.Check
		hostPackageChecks, err = verifyDirArtifacts([]namedDirArtifact{
			{Name: "host-packages", DirArtifact: input.Artifacts.HostPackages},
		})
		checks = append(checks, hostPackageChecks...)
		if err != nil {
			return nil, checks, fmt.Errorf("release-input: %w", err)
		}
	}
	if input.Artifacts.WorkflowsCRDs.Path != "" {
		var workflowsChecks []evidence.Check
		workflowsChecks, err = verifyDirArtifacts([]namedDirArtifact{
			{Name: "workflows-crds", DirArtifact: input.Artifacts.WorkflowsCRDs},
		})
		checks = append(checks, workflowsChecks...)
		if err != nil {
			return nil, checks, fmt.Errorf("release-input: %w", err)
		}
	}
	checks = append(checks, dirChecks...)
	if dirErr != nil {
		return nil, checks, fmt.Errorf("release-input: %w", dirErr)
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
			ID:              evidence.SanitizeIDSegment(artifact.Name) + "-manifest",
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

func toFileArtifacts(rootDir string, artifacts []fileArtifact) []FileArtifact {
	out := make([]FileArtifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		out = append(out, toFileArtifact(rootDir, artifact))
	}
	return out
}

func toFileArtifact(rootDir string, artifact fileArtifact) FileArtifact {
	if strings.TrimSpace(artifact.Path) == "" {
		return FileArtifact{}
	}
	return FileArtifact{
		Path:           filepath.Join(rootDir, artifact.Path),
		Digest:         artifact.Digest,
		SizeBytes:      artifact.SizeBytes,
		Signature:      strings.TrimSpace(artifact.Signature),
		ImageReference: strings.TrimSpace(artifact.ImageReference),
	}
}

func toDirArtifact(rootDir string, artifact dirArtifact) DirArtifact {
	if strings.TrimSpace(artifact.Path) == "" {
		return DirArtifact{}
	}
	return DirArtifact{
		Path:           filepath.Join(rootDir, artifact.Path),
		ManifestDigest: artifact.ManifestDigest,
	}
}
