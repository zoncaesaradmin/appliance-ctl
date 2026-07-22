package install

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
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
	RegistryChartPath string
	ArgoChartPath     string
	ArgoCRDPaths      []string
	ConfigurationPath string
	// WorkspaceProvisionerImageReference is the appliance-owned generic
	// image used by builder workspace provisioning workflows.
	WorkspaceProvisionerImageReference string
	// BuilderImageReference is the single bundled builder/dev-container image
	// used by Argo build pods (automation-dev).
	BuilderImageReference string
	ZotImageReference     string

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
	chartPath, err := applianceChartPath(b)
	if err != nil {
		return Resolved{}, checks, fmt.Errorf("install: %w", err)
	}
	argoChartPath := optionalArgoChartPath(b)
	registryChartPath := ""
	if strings.TrimSpace(b.Compatibility.ZotVersion) != "" {
		registryChartPath, err = requiredRegistryChartPath(b)
		if err != nil {
			return Resolved{}, checks, fmt.Errorf("install: %w", err)
		}
	}
	zonctlBinaryPath, err := applianceBinaryPath(b, "zonctl-real")
	if err != nil {
		return Resolved{}, checks, fmt.Errorf("install: %w", err)
	}
	configurationPath, err := configurationPath(b)
	if err != nil {
		return Resolved{}, checks, fmt.Errorf("install: %w", err)
	}
	argoCRDPaths := crdPaths(b)
	if argoChartPath != "" && len(argoCRDPaths) == 0 {
		return Resolved{}, checks, fmt.Errorf("install: bundle has an argo-workflows chart but no argo-crds artifact; the workflow controller cannot start without its CRDs")
	}

	var k3sImages, ociImages []images.Image
	for _, e := range b.Entries("k3s-images") {
		name, requireReference := imageName(e)
		k3sImages = append(k3sImages, images.Image{Name: name, ArchivePath: e.Path, ExpectedDigest: e.Digest, Category: images.CategoryK3sPlatform, RequireReference: requireReference})
	}
	for _, e := range b.Entries("oci-images") {
		name, requireReference := imageName(e)
		category := images.CategoryApplication
		if isZotImageReference(e.ImageReference) || isWorkflowDependencyReference(e.ImageReference) {
			category = images.CategoryDependency
		}
		ociImages = append(ociImages, images.Image{Name: name, ArchivePath: e.Path, ExpectedDigest: e.Digest, Category: category, RequireReference: requireReference})
	}
	workspaceProvisionerImageReference := workspaceProvisionerImageReference(b)
	builderImageReference := builderImageReference(b)
	zotImageReference := ""
	if strings.TrimSpace(b.Compatibility.ZotVersion) != "" {
		zotImageReference, err = requiredZotImageReference(b)
		if err != nil {
			return Resolved{}, checks, fmt.Errorf("install: %w", err)
		}
	}

	return Resolved{
		BundleVersion:                      b.BundleVersion,
		ReleaseID:                          b.ReleaseID,
		Compatibility:                      b.Compatibility,
		ZonctlBinaryPath:                   zonctlBinaryPath,
		K3sBinaryPath:                      k3sBinaryPath,
		ChartPath:                          chartPath,
		RegistryChartPath:                  registryChartPath,
		ArgoChartPath:                      argoChartPath,
		ArgoCRDPaths:                       argoCRDPaths,
		ConfigurationPath:                  configurationPath,
		WorkspaceProvisionerImageReference: workspaceProvisionerImageReference,
		BuilderImageReference:              builderImageReference,
		ZotImageReference:                  zotImageReference,
		K3sImages:                          k3sImages,
		OCIImages:                          ociImages,
	}, checks, nil
}

func isZotImageReference(ref string) bool {
	return strings.HasPrefix(strings.TrimSpace(ref), "registry.local/zot@sha256:")
}

func isWorkflowDependencyReference(ref string) bool {
	ref = strings.TrimSpace(ref)
	return strings.Contains(ref, "/argoproj/workflow-controller:") ||
		strings.Contains(ref, "/argoproj/argoexec:")
}

func requiredZotImageReference(b *bundle.Bundle) (string, error) {
	var found string
	for _, e := range b.Entries("oci-images") {
		if !isZotImageReference(e.ImageReference) {
			continue
		}
		if found != "" {
			return "", fmt.Errorf("bundle has multiple zot image entries")
		}
		found = strings.TrimSpace(e.ImageReference)
	}
	if found == "" {
		return "", fmt.Errorf("bundle has no canonical registry.local/zot@sha256 image entry")
	}
	return found, nil
}

func imageName(e bundle.Entry) (string, bool) {
	if e.ImageReference != "" {
		return e.ImageReference, true
	}
	return e.Path, false
}

func workspaceProvisionerImageReference(b *bundle.Bundle) string {
	for _, e := range b.Entries("oci-images") {
		ref := strings.TrimSpace(e.ImageReference)
		if strings.Contains(ref, "/workspace-provisioner@sha256:") ||
			strings.HasPrefix(ref, "workspace-provisioner@sha256:") ||
			strings.Contains(ref, "/alpine/git@sha256:") {
			return ref
		}
	}
	return ""
}

func builderImageReference(b *bundle.Bundle) string {
	for _, e := range b.Entries("oci-images") {
		ref := strings.TrimSpace(e.ImageReference)
		if strings.Contains(ref, "/automation-dev@sha256:") ||
			strings.HasPrefix(ref, "automation-dev@sha256:") {
			return ref
		}
	}
	return ""
}

func applianceChartPath(b *bundle.Bundle) (string, error) {
	entries := b.Entries("chart")
	if len(entries) == 0 {
		return "", fmt.Errorf("bundle has no chart entry")
	}
	if len(entries) == 1 {
		return entries[0].Path, nil
	}
	for _, e := range entries {
		base := strings.ToLower(filepath.Base(e.Path))
		if base == "appliance-chart.tgz" || strings.HasPrefix(base, "appliance-chart-") {
			return e.Path, nil
		}
	}
	return "", fmt.Errorf("bundle has multiple chart entries but none named appliance-chart-*")
}

func optionalArgoChartPath(b *bundle.Bundle) string {
	for _, e := range b.Entries("chart") {
		base := strings.ToLower(filepath.Base(e.Path))
		if strings.HasPrefix(base, "argo-workflows") {
			return e.Path
		}
	}
	return ""
}

func requiredRegistryChartPath(b *bundle.Bundle) (string, error) {
	var found string
	for _, e := range b.Entries("chart") {
		base := strings.ToLower(filepath.Base(e.Path))
		if !strings.HasPrefix(base, "appliance-registry-") {
			continue
		}
		if found != "" {
			return "", fmt.Errorf("bundle has multiple appliance-registry chart entries")
		}
		found = e.Path
	}
	if found == "" {
		return "", fmt.Errorf("bundle has no appliance-registry chart entry")
	}
	return found, nil
}

func crdPaths(b *bundle.Bundle) []string {
	entries := b.Entries("kubernetes-crds")
	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		paths = append(paths, e.Path)
	}
	sort.Strings(paths)
	return paths
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
