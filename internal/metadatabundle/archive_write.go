package metadatabundle

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

// WriteMinimalArchive writes a tiny but extractable appliance metadata-bundle
// archive for tests and local fixtures. profileIDs must be non-empty.
func WriteMinimalArchive(destPath, metadataVersion string, profileIDs ...string) error {
	metadataVersion = strings.TrimSpace(metadataVersion)
	if metadataVersion == "" {
		return fmt.Errorf("metadatabundle: metadata version is required")
	}
	if len(profileIDs) == 0 {
		return fmt.Errorf("metadatabundle: at least one profile id is required")
	}
	dirName := DirectoryName(metadataVersion)
	var profiles strings.Builder
	profiles.WriteString("profiles:\n")
	for _, id := range profileIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		fmt.Fprintf(&profiles, "  %s:\n    displayName: %q\n    description: test\n    capabilities: [base, host]\n", id, id)
	}

	files := map[string]string{
		dirName + "/bundle.yaml": fmt.Sprintf(`apiVersion: metadata.zon/v1
kind: ApplianceMetadataBundle
metadata:
  metadataVersion: %q
  softwareVersion: %q
  createdAt: "2026-01-01T00:00:00Z"
`, metadataVersion, strings.TrimSuffix(metadataVersion, ".0")),
		dirName + "/profiles/catalog.yaml":     profiles.String(),
		dirName + "/capabilities/catalog.yaml": "capabilities:\n  base:\n    displayName: base\n",
	}

	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(zw)
	now := time.Unix(0, 0).UTC()
	for name, body := range files {
		hdr := &tar.Header{
			Name:    name,
			Mode:    0o644,
			Size:    int64(len(body)),
			ModTime: now,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			tw.Close()
			zw.Close()
			return err
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			tw.Close()
			zw.Close()
			return err
		}
	}
	if err := tw.Close(); err != nil {
		zw.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o750); err != nil {
		return err
	}
	return os.WriteFile(destPath, buf.Bytes(), 0o640)
}
