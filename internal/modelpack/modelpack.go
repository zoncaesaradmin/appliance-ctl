// Package modelpack defines the signed offline model-pack contract used to
// deliver LLM weights separately from the main appliance air-gap bundle.
package modelpack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

const (
	KindV1            = "appliance.modelpack/v1"
	ManifestFileName  = "manifest.json"
	SignatureFileName = "manifest.json.sig"
)

// Manifest is the verified description of one model pack.
type Manifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	Kind          string `json:"kind"`
	ModelID       string `json:"modelId"`
	Runtime       string `json:"runtime"`
	Digest        string `json:"digest"`
	SizeBytes     int64  `json:"sizeBytes"`
	MinRAMGB      int    `json:"minRAMGB"`
	Compatibility struct {
		InferenceVersion string `json:"inferenceVersion"`
	} `json:"compatibility"`
	Blobs []Blob `json:"blobs"`
}

// Blob is one content-addressed weight file inside the pack directory.
type Blob struct {
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	SizeBytes int64  `json:"sizeBytes"`
}

// Pack is a verified model pack rooted on disk.
type Pack struct {
	RootDir  string
	Manifest Manifest
}

// Load verifies manifest.json (+ optional detached signature), every blob
// digest/size, and returns the pack. When pub is nil, signature checks are
// skipped only if no signature file is present; a present signature without
// a key fails closed.
func Load(rootDir string, pub *verify.PublicKey) (*Pack, error) {
	rootDir = strings.TrimSpace(rootDir)
	if rootDir == "" {
		return nil, fmt.Errorf("modelpack: root directory must not be empty")
	}
	manifestPath := filepath.Join(rootDir, ManifestFileName)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("modelpack: read manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("modelpack: parse manifest: %w", err)
	}
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}

	sigPath := filepath.Join(rootDir, SignatureFileName)
	if _, err := os.Stat(sigPath); err == nil {
		artifacts := []verify.Artifact{{
			Name:              "modelpack-manifest",
			Path:              manifestPath,
			ExpectedDigest:    digestOf(data),
			ExpectedSizeBytes: int64(len(data)),
			SignaturePath:     sigPath,
		}}
		if _, err := verify.VerifyArtifacts(pub, artifacts); err != nil {
			return nil, fmt.Errorf("modelpack: verify signature: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("modelpack: stat signature: %w", err)
	} else if pub != nil {
		// Signature is required when a verification key is supplied.
		return nil, fmt.Errorf("modelpack: missing %s (signed packs are required when a public key is supplied)", SignatureFileName)
	}

	var total int64
	for idx, blob := range manifest.Blobs {
		blobPath := filepath.Join(rootDir, filepath.Clean(blob.Path))
		if !strings.HasPrefix(blobPath, rootDir+string(os.PathSeparator)) && blobPath != rootDir {
			return nil, fmt.Errorf("modelpack: blobs[%d].path escapes pack root", idx)
		}
		info, err := os.Stat(blobPath)
		if err != nil {
			return nil, fmt.Errorf("modelpack: blobs[%d]: %w", idx, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("modelpack: blobs[%d] is not a regular file", idx)
		}
		if info.Size() != blob.SizeBytes {
			return nil, fmt.Errorf("modelpack: blobs[%d] size %d != declared %d", idx, info.Size(), blob.SizeBytes)
		}
		got, err := fileDigest(blobPath)
		if err != nil {
			return nil, fmt.Errorf("modelpack: blobs[%d] digest: %w", idx, err)
		}
		if got != strings.TrimSpace(blob.Digest) {
			return nil, fmt.Errorf("modelpack: blobs[%d] digest mismatch", idx)
		}
		total += blob.SizeBytes
	}
	if manifest.SizeBytes != 0 && total != manifest.SizeBytes {
		return nil, fmt.Errorf("modelpack: sizeBytes %d != sum of blobs %d", manifest.SizeBytes, total)
	}
	return &Pack{RootDir: rootDir, Manifest: manifest}, nil
}

// Import copies verified blob files into modelsDir/<modelId>/ and writes a
// copy of the manifest beside them. modelsDir is typically
// /data/zon/inference/models on the appliance host.
func (p *Pack) Import(modelsDir string) (string, error) {
	if p == nil {
		return "", fmt.Errorf("modelpack: pack is nil")
	}
	modelsDir = strings.TrimSpace(modelsDir)
	if modelsDir == "" {
		return "", fmt.Errorf("modelpack: models directory must not be empty")
	}
	modelID := strings.TrimSpace(p.Manifest.ModelID)
	destRoot := filepath.Join(modelsDir, sanitizeModelID(modelID))
	if err := os.MkdirAll(destRoot, 0o2770); err != nil {
		return "", fmt.Errorf("modelpack: create destination: %w", err)
	}
	for _, blob := range p.Manifest.Blobs {
		src := filepath.Join(p.RootDir, filepath.Clean(blob.Path))
		dst := filepath.Join(destRoot, filepath.Base(blob.Path))
		if err := copyFile(src, dst); err != nil {
			return "", fmt.Errorf("modelpack: copy %s: %w", blob.Path, err)
		}
	}
	manifestBytes, err := json.MarshalIndent(p.Manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("modelpack: encode manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(destRoot, ManifestFileName), append(manifestBytes, '\n'), 0o640); err != nil {
		return "", fmt.Errorf("modelpack: write destination manifest: %w", err)
	}
	return destRoot, nil
}

func validateManifest(m Manifest) error {
	if m.SchemaVersion != 1 {
		return fmt.Errorf("modelpack: unsupported schemaVersion %d", m.SchemaVersion)
	}
	if strings.TrimSpace(m.Kind) != KindV1 {
		return fmt.Errorf("modelpack: kind must be %q", KindV1)
	}
	if strings.TrimSpace(m.ModelID) == "" {
		return fmt.Errorf("modelpack: modelId must not be empty")
	}
	if strings.TrimSpace(m.Runtime) == "" {
		return fmt.Errorf("modelpack: runtime must not be empty")
	}
	if strings.TrimSpace(m.Compatibility.InferenceVersion) == "" {
		return fmt.Errorf("modelpack: compatibility.inferenceVersion must not be empty")
	}
	if len(m.Blobs) == 0 {
		return fmt.Errorf("modelpack: blobs must not be empty")
	}
	for idx, blob := range m.Blobs {
		if strings.TrimSpace(blob.Path) == "" {
			return fmt.Errorf("modelpack: blobs[%d].path must not be empty", idx)
		}
		if !strings.HasPrefix(strings.TrimSpace(blob.Digest), "sha256:") {
			return fmt.Errorf("modelpack: blobs[%d].digest must be sha256:...", idx)
		}
		if blob.SizeBytes <= 0 {
			return fmt.Errorf("modelpack: blobs[%d].sizeBytes must be positive", idx)
		}
	}
	return nil
}

func sanitizeModelID(id string) string {
	id = strings.TrimSpace(id)
	replacer := strings.NewReplacer("/", "_", ":", "_", " ", "_")
	return replacer.Replace(id)
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
