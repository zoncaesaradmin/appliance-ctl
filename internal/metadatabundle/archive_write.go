package metadatabundle

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

// InstallTestProfileCatalog mirrors the signed metadata policy used in zonctl
// install/upgrade fixtures.
func InstallTestProfileCatalog() map[string][]string {
	return map[string][]string{
		"core":                          {"base", "files"},
		"builder":                       {"base", "host", "files", "workflows", "build", "artifact"},
		"storage":                       {"base", "host", "files", "artifact"},
		"landns":                        {"base", "host", "files", "dns"},
		"storage-landns":                {"base", "host", "files", "artifact", "dns"},
		"builder-landns":                {"base", "host", "files", "workflows", "build", "artifact", "dns"},
		"builder-storage-landns":        {"base", "host", "files", "workflows", "build", "artifact", "dns"},
		"lanllm":                        {"base", "inference"},
		"builder-lanllm":                {"base", "host", "files", "workflows", "build", "artifact", "inference"},
		"builder-lanllm-storage-landns": {"base", "host", "files", "workflows", "build", "artifact", "dns", "inference"},
		"training":                      {"base", "files", "video"},
	}
}

// WriteInstallTestArchive writes the standard metadata-bundle archive used by
// install/upgrade/source tests.
func WriteInstallTestArchive(destPath, metadataVersion string) error {
	return WriteProfileCatalogArchive(destPath, metadataVersion, InstallTestProfileCatalog())
}

// WriteProfileCatalogArchive writes an extractable metadata-bundle archive with
// explicit profile capability mappings.
func WriteProfileCatalogArchive(destPath, metadataVersion string, profiles map[string][]string) error {
	metadataVersion = strings.TrimSpace(metadataVersion)
	if metadataVersion == "" {
		return fmt.Errorf("metadatabundle: metadata version is required")
	}
	if len(profiles) == 0 {
		return fmt.Errorf("metadatabundle: at least one profile is required")
	}
	dirName := DirectoryName(metadataVersion)
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)

	var catalog strings.Builder
	catalog.WriteString("profiles:\n")
	for _, name := range names {
		caps := profiles[name]
		fmt.Fprintf(&catalog, "  %s:\n    displayName: %q\n    description: test\n    capabilities: [%s]\n", name, name, strings.Join(caps, ", "))
	}

	files := map[string]string{
		dirName + "/bundle.yaml": fmt.Sprintf(`apiVersion: metadata.zon/v1
kind: ApplianceMetadataBundle
schemaVersion: 1
metadata:
  metadataVersion: %q
  softwareVersion: %q
  createdAt: "2026-01-01T00:00:00Z"
sections:
  - profiles
  - capabilities
`, metadataVersion, strings.TrimSuffix(metadataVersion, ".0")),
		dirName + "/profiles/catalog.yaml":     catalog.String(),
		dirName + "/capabilities/catalog.yaml": installTestCapabilitiesYAML(),
	}
	return writeArchiveFiles(destPath, files)
}

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
	profiles := make(map[string][]string, len(profileIDs))
	for _, id := range profileIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		profiles[id] = []string{"base", "host"}
	}
	return WriteProfileCatalogArchive(destPath, metadataVersion, profiles)
}

func installTestCapabilitiesYAML() string {
	return `capabilities:
  base:
    displayName: Base
    requires: []
  host:
    displayName: Host
    requires: [base]
  files:
    displayName: Files
    requires: [base]
  workflows:
    displayName: Workflows
    requires: [base]
  build:
    displayName: Build
    requires: [base, host, workflows, artifact]
  artifact:
    displayName: Artifact
    requires: [base]
  dns:
    displayName: LAN DNS
    requires: [base, host]
  inference:
    displayName: Inference
    requires: [base]
  video:
    displayName: Video
    requires: [base]
`
}

func writeArchiveFiles(destPath string, files map[string]string) error {
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
