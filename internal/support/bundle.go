// Package support builds redacted diagnostic support bundles: a tar.gz
// archive of installed-state, evidence reports, and diagnostics, with
// every registered secret scrubbed before anything is written to disk.
// See "Checks are... included in support bundles with secrets redacted"
// in docs/release-plan.md.
package support

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/redact"
)

// Source is one named document to include in the bundle.
type Source struct {
	Name    string // file name within the archive, e.g. "installed-state.json"
	Content []byte
}

// ManifestEntry describes one archived file in the bundle's own
// inventory manifest.
type ManifestEntry struct {
	Name      string `json:"name"`
	Digest    string `json:"digest"`
	SizeBytes int    `json:"sizeBytes"`
}

// Build writes a tar.gz support bundle to outputPath containing every
// source plus a manifest.json inventory (name/digest/size, computed after
// redaction). Every source's content is passed through redactor.Redact
// before it is ever written to a header, buffer, or disk, so a secret
// that leaked into a source document is still scrubbed from the bundle.
func Build(outputPath string, sources []Source, redactor *redact.Redactor) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("support: create %s: %w", outputPath, err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	now := time.Now()
	var manifestEntries []ManifestEntry

	for _, s := range sources {
		redacted := []byte(redactor.Redact(string(s.Content)))
		digest := sha256.Sum256(redacted)
		manifestEntries = append(manifestEntries, ManifestEntry{
			Name:      s.Name,
			Digest:    "sha256:" + hex.EncodeToString(digest[:]),
			SizeBytes: len(redacted),
		})

		if err := writeTarFile(tw, s.Name, redacted, now); err != nil {
			return fmt.Errorf("support: write %s: %w", s.Name, err)
		}
	}

	manifestBytes, err := json.MarshalIndent(manifestEntries, "", "  ")
	if err != nil {
		return fmt.Errorf("support: marshal manifest: %w", err)
	}
	if err := writeTarFile(tw, "manifest.json", manifestBytes, now); err != nil {
		return fmt.Errorf("support: write manifest.json: %w", err)
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("support: close tar writer: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("support: close gzip writer: %w", err)
	}
	return f.Close()
}

func writeTarFile(tw *tar.Writer, name string, content []byte, modTime time.Time) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o640,
		Size:    int64(len(content)),
		ModTime: modTime,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(content)
	return err
}

// Extract reads a support bundle back into memory, keyed by archive
// entry name. It exists for tests and future inspection tooling.
func Extract(path string) (map[string][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("support: open %s: %w", path, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("support: open gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("support: read tar entry: %w", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("support: read %s: %w", hdr.Name, err)
		}
		out[hdr.Name] = data
	}
	return out, nil
}
