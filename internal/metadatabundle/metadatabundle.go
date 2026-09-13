// Package metadatabundle extracts and validates signed appliance metadata-bundle
// archives during install/upgrade so the control plane can seed its active
// metadata from a host-visible tree.
package metadatabundle

import (
	"archive/tar"
	"fmt"
	"github.com/zoncaesaradmin/appliance-ctl/internal/runtimeconfig"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"
	"gopkg.in/yaml.v3"

	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

// SeedResult is the outcome of staging a metadata-bundle archive and extracting
// it onto the host for control-plane use.
type SeedResult struct {
	MetadataVersion string
	Digest          string
	ExtractedDir    string
	ArchivePath     string
}

type profileCatalogFile struct {
	Profiles map[string]ProfileDefinition `yaml:"profiles"`
}

// ProfileDefinition is the policy-relevant portion of one metadata profile.
// It intentionally contains only the profile-to-capability mapping consumed by
// zonctl; display text remains control-plane metadata.
type ProfileDefinition struct {
	Capabilities []string `yaml:"capabilities"`
}

// VersionFromArchiveName derives X.Y.Z.N from appliance-metadata-bundle-X.Y.Z.N.tar.zst.
func VersionFromArchiveName(name string) (string, error) {
	base := filepath.Base(name)
	version := strings.TrimSuffix(base, ".tar.zst")
	version = strings.TrimPrefix(version, "appliance-metadata-bundle-")
	if version == "" || version == base {
		return "", fmt.Errorf("metadatabundle: unexpected archive name %q", base)
	}
	return version, nil
}

// DirectoryName returns appliance-metadata-bundle-<metadataVersion>.
func DirectoryName(metadataVersion string) string {
	return "appliance-metadata-bundle-" + strings.TrimSpace(metadataVersion)
}

// ExtractArchive extracts a .tar.zst metadata bundle into destParent and returns
// the top-level directory path.
func ExtractArchive(archivePath, destParent string) (string, error) {
	if err := os.MkdirAll(destParent, 0o755); err != nil {
		return "", err
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("metadatabundle: zstd reader: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	var topLevel string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("metadatabundle: tar: %w", err)
		}
		name := filepath.Clean(hdr.Name)
		if name == "." || name == "" || strings.HasPrefix(name, "..") {
			return "", fmt.Errorf("metadatabundle: path traversal rejected: %q", hdr.Name)
		}
		parts := strings.Split(filepath.ToSlash(name), "/")
		if len(parts) == 0 || parts[0] == "" {
			continue
		}
		if topLevel == "" {
			topLevel = parts[0]
		} else if parts[0] != topLevel {
			return "", fmt.Errorf("metadatabundle: archive must contain exactly one top-level directory")
		}
		target := filepath.Join(destParent, filepath.FromSlash(name))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return "", err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return "", err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode)&0o644)
			if err != nil {
				return "", err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return "", err
			}
			out.Close()
		default:
			return "", fmt.Errorf("metadatabundle: unsupported tar entry type %v for %q", hdr.Typeflag, hdr.Name)
		}
	}
	if topLevel == "" {
		return "", fmt.Errorf("metadatabundle: empty archive")
	}
	return filepath.Join(destParent, topLevel), nil
}

// LoadProfileCatalogDirectory reads the profile policy from an extracted,
// verified metadata-bundle directory.
func LoadProfileCatalogDirectory(dir string) (map[string]ProfileDefinition, error) {
	data, err := os.ReadFile(filepath.Join(dir, "profiles", "catalog.yaml"))
	if err != nil {
		return nil, fmt.Errorf("metadatabundle: read profiles catalog: %w", err)
	}
	var catalog profileCatalogFile
	if err := yaml.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("metadatabundle: parse profiles catalog: %w", err)
	}
	if len(catalog.Profiles) == 0 {
		return nil, fmt.Errorf("metadatabundle: profiles catalog is empty")
	}
	return catalog.Profiles, nil
}

// LoadProfileCatalogArchive reads the same policy directly from the signed
// bundle archive before installation. This avoids a second, code-owned list of
// profile capability mappings in zonctl.
func LoadProfileCatalogArchive(archivePath string) (map[string]ProfileDefinition, error) {
	var catalog profileCatalogFile
	if err := readCatalogArchive(archivePath, "profiles/catalog.yaml", &catalog); err != nil {
		return nil, err
	}
	if len(catalog.Profiles) == 0 {
		return nil, fmt.Errorf("metadatabundle: profiles catalog in archive is empty")
	}
	return catalog.Profiles, nil
}

type PackageDefinition struct {
	Capabilities []string                                `yaml:"capabilities"`
	Runtimes     map[string]runtimeconfig.Implementation `yaml:"runtimes"`
}

func LoadPackageCatalogArchive(archivePath string) (map[string]PackageDefinition, error) {
	var catalog struct {
		Packages map[string]PackageDefinition `yaml:"packages"`
	}
	if err := readCatalogArchive(archivePath, "packages/catalog.yaml", &catalog); err != nil {
		return nil, err
	}
	if len(catalog.Packages) == 0 {
		return nil, fmt.Errorf("metadatabundle: packages catalog in archive is empty")
	}
	return catalog.Packages, nil
}

// ResolvePackage selects the explicitly selected package that provides a capability.
// Engine identity is provided by package metadata, never inferred from an image
// name, host GPU detection, or an unverified operator values file.
func ResolvePackage(packages map[string]PackageDefinition, capability, packageID string) (runtimeconfig.Selection, error) {
	var selected runtimeconfig.Selection
	for id, pkg := range packages {
		if packageID != "" && id != packageID {
			continue
		}
		runtime, ok := pkg.Runtimes[capability]
		provides := false
		for _, c := range pkg.Capabilities {
			provides = provides || c == capability
		}
		if !provides {
			continue
		}
		if !ok || strings.TrimSpace(runtime.Engine) == "" || strings.TrimSpace(id) == "" {
			return runtimeconfig.Selection{}, fmt.Errorf("metadatabundle: invalid runtime declaration in package %q", id)
		}
		if selected.Package != "" {
			return runtimeconfig.Selection{}, fmt.Errorf("metadatabundle: capability %s is provided by both %s and %s", capability, selected.Package, id)
		}
		selected = runtimeconfig.Selection{Package: id, Engine: runtime.Engine}
	}
	if selected.Package == "" {
		return selected, fmt.Errorf("metadatabundle: no package provides capability %s", capability)
	}
	return selected, nil
}

func readCatalogArchive(archivePath, catalogPath string, target any) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {
		return fmt.Errorf("metadatabundle: open archive: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("metadatabundle: read archive: %w", err)
		}
		name := filepath.ToSlash(filepath.Clean(hdr.Name))
		if !strings.HasSuffix(name, "/"+catalogPath) || hdr.Typeflag != tar.TypeReg {
			continue
		}
		if found {
			return fmt.Errorf("metadatabundle: duplicate %s in archive", catalogPath)
		}
		if hdr.Size < 0 || hdr.Size > 1024*1024 {
			return fmt.Errorf("metadatabundle: %s entry has invalid size %d", catalogPath, hdr.Size)
		}
		data, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
		if err != nil {
			return err
		}
		if int64(len(data)) != hdr.Size {
			return fmt.Errorf("metadatabundle: truncated %s in archive", catalogPath)
		}
		if err := yaml.Unmarshal(data, target); err != nil {
			return fmt.Errorf("metadatabundle: parse %s: %w", catalogPath, err)
		}
		found = true
	}
	if !found {
		return fmt.Errorf("metadatabundle: archive has no %s", catalogPath)
	}
	return nil
}

// ProfileIDs returns sorted profile ids from profiles/catalog.yaml under dir.
func ProfileIDs(dir string) ([]string, error) {
	profiles, err := LoadProfileCatalogDirectory(dir)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(profiles))
	for id := range profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// ValidateProfile reports whether profileID is present in the extracted catalog.
func ValidateProfile(dir, profileID string) error {
	ids, err := ProfileIDs(dir)
	if err != nil {
		return err
	}
	profileID = strings.TrimSpace(profileID)
	for _, id := range ids {
		if id == profileID {
			return nil
		}
	}
	return fmt.Errorf("metadatabundle: profile %q is not defined in the metadata bundle (known: %s)", profileID, strings.Join(ids, ", "))
}

// SeedHost copies the archive into archiveDestDir for audit, extracts it under
// hostExtractDir, optionally validates profileID, and returns digests/paths.
func SeedHost(archivePath, archiveDestDir, hostExtractDir, profileID string) (SeedResult, error) {
	version, err := VersionFromArchiveName(archivePath)
	if err != nil {
		return SeedResult{}, err
	}
	if err := os.MkdirAll(archiveDestDir, 0o750); err != nil {
		return SeedResult{}, err
	}
	data, err := os.ReadFile(archivePath)
	if err != nil {
		return SeedResult{}, err
	}
	archiveDest := filepath.Join(archiveDestDir, filepath.Base(archivePath))
	if err := os.WriteFile(archiveDest, data, 0o640); err != nil {
		return SeedResult{}, err
	}
	digest, err := verify.Digest(archiveDest)
	if err != nil {
		return SeedResult{}, err
	}

	wantDir := filepath.Join(hostExtractDir, DirectoryName(version))
	_ = os.RemoveAll(wantDir)
	extracted, err := ExtractArchive(archiveDest, hostExtractDir)
	if err != nil {
		return SeedResult{}, err
	}
	if filepath.Base(extracted) != DirectoryName(version) {
		_ = os.RemoveAll(wantDir)
		if err := os.Rename(extracted, wantDir); err != nil {
			return SeedResult{}, err
		}
		extracted = wantDir
	}
	if strings.TrimSpace(profileID) != "" {
		if err := ValidateProfile(extracted, profileID); err != nil {
			return SeedResult{}, err
		}
	}
	return SeedResult{
		MetadataVersion: version,
		Digest:          digest,
		ExtractedDir:    extracted,
		ArchivePath:     archiveDest,
	}, nil
}
