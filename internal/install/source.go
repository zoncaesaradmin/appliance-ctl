package install

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/zoncaesaradmin/appliance-ctl/internal/bundle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/images"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

// Resolved is every artifact the install sequence needs, as verified
// local filesystem paths loaded from the signed appliance bundle.
// Install and Upgrade consume these paths without caring about bundle
// layout details.
type Resolved struct {
	BundleVersion    string
	ReleaseID        string
	Compatibility    bundle.Compatibility
	ZonctlBinaryPath string

	K3sBinaryPath     string
	ChartPath         string
	ConfigurationPath string

	// K3sImages and OCIImages are preloaded directly into the K3s image
	// store before chart application so the appliance can run with public
	// egress denied.
	K3sImages []images.Image
	OCIImages []images.Image
}

// Source acquires and verifies every artifact Install needs, returning
// local paths. V1 uses a signed local bundle only, but the interface
// keeps the orchestration logic decoupled from bundle layout details.
type Source interface {
	Resolve(ctx context.Context) (Resolved, []evidence.Check, error)
}

// OfflineSource resolves artifacts from a verified local air-gap bundle.
type OfflineSource struct {
	BundleDir string
	PublicKey *verify.PublicKey
}

func (s OfflineSource) Resolve(ctx context.Context) (Resolved, []evidence.Check, error) {
	b, checks, err := bundle.Load(s.BundleDir, s.PublicKey)
	if err != nil {
		return Resolved{}, checks, fmt.Errorf("install: %w", err)
	}

	k3sBinaryPath, ok := b.Path("k3s-binary")
	if !ok {
		return Resolved{}, checks, fmt.Errorf("install: bundle has no k3s-binary entry")
	}
	chartPath, ok := b.Path("chart")
	if !ok {
		return Resolved{}, checks, fmt.Errorf("install: bundle has no chart entry")
	}
	zonctlBinaryPath, err := applianceBinaryPath(b, "zonctl-real")
	if err != nil {
		return Resolved{}, checks, fmt.Errorf("install: %w", err)
	}
	configurationPath, err := configurationPath(b)
	if err != nil {
		return Resolved{}, checks, fmt.Errorf("install: %w", err)
	}

	var k3sImages, ociImages []images.Image
	for _, e := range b.Entries("k3s-images") {
		k3sImages = append(k3sImages, images.Image{Name: imageName(e), ArchivePath: e.Path, ExpectedDigest: e.Digest, Category: images.CategoryK3sPlatform})
	}
	for _, e := range b.Entries("oci-images") {
		ociImages = append(ociImages, images.Image{Name: imageName(e), ArchivePath: e.Path, ExpectedDigest: e.Digest, Category: images.CategoryApplication})
	}

	return Resolved{
		BundleVersion:     b.BundleVersion,
		ReleaseID:         b.ReleaseID,
		Compatibility:     b.Compatibility,
		ZonctlBinaryPath:  zonctlBinaryPath,
		K3sBinaryPath:     k3sBinaryPath,
		ChartPath:         chartPath,
		ConfigurationPath: configurationPath,
		K3sImages:         k3sImages,
		OCIImages:         ociImages,
	}, checks, nil
}

func imageName(e bundle.Entry) string {
	if e.ImageReference != "" {
		return e.ImageReference
	}
	return e.Path
}

func configurationPath(b *bundle.Bundle) (string, error) {
	entries := b.Entries("configuration")
	if len(entries) == 0 {
		return "", fmt.Errorf("bundle has no configuration entry")
	}
	if len(entries) == 1 {
		return entries[0].Path, nil
	}
	for _, e := range entries {
		base := strings.ToLower(filepath.Base(e.Path))
		if base == "values.yaml" || base == "values.yml" {
			return e.Path, nil
		}
	}
	return "", fmt.Errorf("bundle has multiple configuration entries but none is values.yaml/values.yml")
}

func applianceBinaryPath(b *bundle.Bundle, baseName string) (string, error) {
	for _, e := range b.Entries("appliance") {
		if strings.EqualFold(filepath.Base(e.Path), baseName) {
			return e.Path, nil
		}
	}
	return "", fmt.Errorf("bundle has no appliance entry named %s", baseName)
}
