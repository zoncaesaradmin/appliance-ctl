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
	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
	"github.com/zoncaesaradmin/appliance-ctl/internal/zonctlhost"
)

// Resolved is every artifact the install sequence needs, as verified
// local filesystem paths loaded from the signed appliance bundle.
// Install and Upgrade consume these paths without caring about bundle
// layout details.
type Resolved struct {
	BundleVersion    string
	ReleaseID        string
	HostBaseline     bundle.HostBaseline
	Compatibility    bundle.Compatibility
	EffectiveProfile string
	CatalogPath      string
	HostEnabled      bool
	ArtifactEnabled  bool
	DNSEnabled       bool
	BuildEnabled     bool
	WorkflowsEnabled bool
	ZonctlBinaryPath string
	// HelperBinaryPaths are durable host tools (currently helm) installed
	// next to zonctl-real so status/verify work without the temp bundle PATH.
	HelperBinaryPaths []string

	K3sBinaryPath       string
	ChartPath           string
	RegistryChartPath   string
	DNSChartPath        string
	ArgoChartPath       string
	ArgoCRDPaths        []string
	ConfigurationPath   string
	HostAgentBinaryPath string
	HostPackagesRootDir string
	// MetadataBundleArchivePath is the signed base appliance metadata-bundle archive.
	MetadataBundleArchivePath string
	// WorkspaceProvisionerImageReference is the appliance-owned generic
	// image used by builder workspace provisioning workflows.
	WorkspaceProvisionerImageReference string
	// BuilderImageReference is the single bundled builder/dev-container image
	// used by Argo build pods (dev-build).
	BuilderImageReference string
	// HostAgentImageReference is the bundled, digest-pinned appliance host
	// agent image reference used by the host capability.
	HostAgentImageReference string
	ZotImageReference       string
	// DNSImageReference is the bundled, digest-pinned registry.local/coredns
	// image reference used for the landns/storage-landns capability.
	DNSImageReference string

	// K3sImages and OCIImages are preloaded directly into the K3s image
	// store before chart application so the appliance can run with public
	// egress denied.
	K3sImages []images.Image
	OCIImages []images.Image
}

// Source acquires and verifies every artifact Install needs, returning
// local paths. V1 uses a signed local bundle only, but the interface
// keeps the orchestration logic decoupled from bundle layout details.
// requestedProfile is the target appliance profile requested by the
// operator (or the caller's current-profile fallback). The source
// resolves it against the bundle's catalog when present, falling back to
// built-ins otherwise, so artifact selection follows the same catalog the
// installer/control plane will later use.
type Source interface {
	Resolve(ctx context.Context, requestedProfile string) (Resolved, []evidence.Check, error)
}

// OfflineSource resolves artifacts from a verified local air-gap bundle.
type OfflineSource struct {
	BundleDir string
	PublicKey *verify.PublicKey
}

func (s OfflineSource) Resolve(ctx context.Context, requestedProfile string) (Resolved, []evidence.Check, error) {
	_ = ctx
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
	zonctlBinaryPath, err := applianceBinaryPath(b, "zonctl-real")
	if err != nil {
		return Resolved{}, checks, fmt.Errorf("install: %w", err)
	}
	helperBinaryPaths, err := zonctlhost.ResolveHelperSourcePaths(filepath.Dir(zonctlBinaryPath))
	if err != nil {
		return Resolved{}, checks, fmt.Errorf("install: %w", err)
	}
	configurationPath, err := configurationPath(b)
	if err != nil {
		return Resolved{}, checks, fmt.Errorf("install: %w", err)
	}
	catalogPath, err := optionalCatalogPath(b)
	if err != nil {
		return Resolved{}, checks, fmt.Errorf("install: %w", err)
	}
	catalog, err := productconfig.LoadCatalog(catalogPath)
	if err != nil {
		return Resolved{}, checks, fmt.Errorf("install: load appliance catalog: %w", err)
	}
	effectiveProfile, err := productconfig.ResolveApplianceProfileWithCatalog(requestedProfile, "", catalog.Profiles)
	if err != nil {
		return Resolved{}, checks, fmt.Errorf("install: %w", err)
	}
	resolvedModules := productconfig.ResolveModulesWithCatalog(effectiveProfile, catalog.Profiles, productconfig.AlwaysEntitled{}, catalog.Modules)
	hostEnabled := productconfig.HostAgentEnabled(resolvedModules)
	artifactEnabled := productconfig.ModuleEnabled(resolvedModules, productconfig.ModuleNameArtifactRegistry)
	dnsEnabled := productconfig.ModuleEnabled(resolvedModules, productconfig.ModuleNameLANDNS)
	buildEnabled := productconfig.ModuleEnabled(resolvedModules, productconfig.ModuleNameBuild)
	workflowsEnabled := productconfig.HasCapabilityInCatalog(effectiveProfile, productconfig.CapabilityWorkflows, catalog.Profiles)

	argoChartPath := ""
	argoCRDPaths := []string(nil)
	if workflowsEnabled {
		argoChartPath = optionalArgoChartPath(b)
		argoCRDPaths = crdPaths(b)
		if argoChartPath != "" && len(argoCRDPaths) == 0 {
			return Resolved{}, checks, fmt.Errorf("install: bundle has an argo-workflows chart but no argo-crds artifact; the workflow controller cannot start without its CRDs")
		}
	}
	registryChartPath := ""
	if artifactEnabled && strings.TrimSpace(b.Compatibility.ZotVersion) != "" {
		registryChartPath, err = requiredRegistryChartPath(b)
		if err != nil {
			return Resolved{}, checks, fmt.Errorf("install: %w", err)
		}
	}
	dnsChartPath := ""
	if dnsEnabled && strings.TrimSpace(b.Compatibility.DNSVersion) != "" {
		dnsChartPath, err = requiredDNSChartPath(b)
		if err != nil {
			return Resolved{}, checks, fmt.Errorf("install: %w", err)
		}
	}
	hostAgentBinaryPath := ""
	if hostEnabled {
		hostAgentBinaryPath, err = applianceBinaryPath(b, "appliance-host-agentd")
		if err != nil {
			return Resolved{}, checks, fmt.Errorf("install: %w", err)
		}
	}
	hostPackagesRootDir := componentRootDir(b, "host-packages")
	metadataBundleArchivePath, err := requiredMetadataBundleArchivePath(b)
	if err != nil {
		return Resolved{}, checks, fmt.Errorf("install: %w", err)
	}

	var k3sImages, ociImages []images.Image
	for _, e := range b.Entries("k3s-images") {
		name, requireReference := imageName(e)
		k3sImages = append(k3sImages, images.Image{Name: name, ArchivePath: e.Path, ExpectedDigest: e.Digest, Category: images.CategoryK3sPlatform, RequireReference: requireReference})
	}
	for _, e := range b.Entries("oci-images") {
		name, requireReference := imageName(e)
		category := images.CategoryApplication
		if isZotImageReference(e.ImageReference) || isDNSImageReference(e.ImageReference) || isWorkflowDependencyReference(e.ImageReference) {
			category = images.CategoryDependency
		}
		ociImages = append(ociImages, images.Image{Name: name, ArchivePath: e.Path, ExpectedDigest: e.Digest, Category: category, RequireReference: requireReference})
	}
	workspaceProvisionerImageReference := workspaceProvisionerImageReference(b)
	builderImageReference := builderImageReference(b)
	hostAgentImageReference := ""
	if hostEnabled {
		hostAgentImageReference, err = requiredHostAgentImageReference(b)
		if err != nil {
			return Resolved{}, checks, fmt.Errorf("install: %w", err)
		}
	}
	zotImageReference := ""
	if artifactEnabled && strings.TrimSpace(b.Compatibility.ZotVersion) != "" {
		zotImageReference, err = requiredZotImageReference(b)
		if err != nil {
			return Resolved{}, checks, fmt.Errorf("install: %w", err)
		}
	}
	dnsImageReference := ""
	if dnsEnabled && strings.TrimSpace(b.Compatibility.DNSVersion) != "" {
		dnsImageReference, err = requiredDNSImageReference(b)
		if err != nil {
			return Resolved{}, checks, fmt.Errorf("install: %w", err)
		}
	}

	return Resolved{
		BundleVersion:                      b.BundleVersion,
		ReleaseID:                          b.ReleaseID,
		HostBaseline:                       b.HostBaseline,
		Compatibility:                      b.Compatibility,
		EffectiveProfile:                   effectiveProfile,
		CatalogPath:                        catalogPath,
		HostEnabled:                        hostEnabled,
		ArtifactEnabled:                    artifactEnabled,
		DNSEnabled:                         dnsEnabled,
		BuildEnabled:                       buildEnabled,
		WorkflowsEnabled:                   workflowsEnabled,
		ZonctlBinaryPath:                   zonctlBinaryPath,
		HelperBinaryPaths:                  helperBinaryPaths,
		K3sBinaryPath:                      k3sBinaryPath,
		ChartPath:                          chartPath,
		RegistryChartPath:                  registryChartPath,
		DNSChartPath:                       dnsChartPath,
		ArgoChartPath:                      argoChartPath,
		ArgoCRDPaths:                       argoCRDPaths,
		ConfigurationPath:                  configurationPath,
		HostAgentBinaryPath:                hostAgentBinaryPath,
		HostPackagesRootDir:                hostPackagesRootDir,
		MetadataBundleArchivePath:          metadataBundleArchivePath,
		WorkspaceProvisionerImageReference: workspaceProvisionerImageReference,
		BuilderImageReference:              builderImageReference,
		HostAgentImageReference:            hostAgentImageReference,
		ZotImageReference:                  zotImageReference,
		DNSImageReference:                  dnsImageReference,
		K3sImages:                          k3sImages,
		OCIImages:                          ociImages,
	}, checks, nil
}

func isZotImageReference(ref string) bool {
	return strings.HasPrefix(strings.TrimSpace(ref), "registry.local/zot@sha256:")
}

func isDNSImageReference(ref string) bool {
	return strings.HasPrefix(strings.TrimSpace(ref), "registry.local/coredns@sha256:")
}

func isWorkflowDependencyReference(ref string) bool {
	ref = strings.TrimSpace(ref)
	return strings.Contains(ref, "/argoproj/workflow-controller:") ||
		strings.Contains(ref, "/argoproj/argoexec:")
}

func isHostAgentImageReference(ref string) bool {
	return strings.HasPrefix(strings.TrimSpace(ref), "registry.local/appliance-host-agent@sha256:")
}

func requiredHostAgentImageReference(b *bundle.Bundle) (string, error) {
	var found string
	for _, e := range b.Entries("oci-images") {
		if !isHostAgentImageReference(e.ImageReference) {
			continue
		}
		if found != "" {
			return "", fmt.Errorf("bundle has multiple appliance host agent image entries")
		}
		found = strings.TrimSpace(e.ImageReference)
	}
	if found == "" {
		return "", fmt.Errorf("bundle has no canonical registry.local/appliance-host-agent@sha256 image entry")
	}
	return found, nil
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

func requiredDNSImageReference(b *bundle.Bundle) (string, error) {
	var found string
	for _, e := range b.Entries("oci-images") {
		if !isDNSImageReference(e.ImageReference) {
			continue
		}
		if found != "" {
			return "", fmt.Errorf("bundle has multiple coredns image entries")
		}
		found = strings.TrimSpace(e.ImageReference)
	}
	if found == "" {
		return "", fmt.Errorf("bundle has no canonical registry.local/coredns@sha256 image entry")
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
		if strings.Contains(ref, "/dev-build@sha256:") ||
			strings.HasPrefix(ref, "dev-build@sha256:") {
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

func requiredDNSChartPath(b *bundle.Bundle) (string, error) {
	var found string
	for _, e := range b.Entries("chart") {
		base := strings.ToLower(filepath.Base(e.Path))
		if !strings.HasPrefix(base, "appliance-dns-") {
			continue
		}
		if found != "" {
			return "", fmt.Errorf("bundle has multiple appliance-dns chart entries")
		}
		found = e.Path
	}
	if found == "" {
		return "", fmt.Errorf("bundle has no appliance-dns chart entry")
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

func requiredMetadataBundleArchivePath(b *bundle.Bundle) (string, error) {
	var found string
	for _, e := range b.Entries("artifacts") {
		base := strings.ToLower(filepath.Base(e.Path))
		if !strings.HasPrefix(base, "appliance-metadata-bundle-") || !strings.HasSuffix(base, ".tar.zst") {
			continue
		}
		if found != "" {
			return "", fmt.Errorf("bundle has multiple appliance metadata-bundle archives")
		}
		found = e.Path
	}
	if found == "" {
		return "", fmt.Errorf("bundle has no appliance-metadata-bundle-*.tar.zst artifact")
	}
	return found, nil
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

func optionalCatalogPath(b *bundle.Bundle) (string, error) {
	var found string
	for _, e := range b.Entries("configuration") {
		base := strings.ToLower(filepath.Base(e.Path))
		if base != "appliance-catalog.json" {
			continue
		}
		if found != "" {
			return "", fmt.Errorf("bundle has multiple configuration entries named appliance-catalog.json")
		}
		found = e.Path
	}
	return found, nil
}

func applianceBinaryPath(b *bundle.Bundle, baseName string) (string, error) {
	for _, e := range b.Entries("appliance") {
		if strings.EqualFold(filepath.Base(e.Path), baseName) {
			return e.Path, nil
		}
	}
	return "", fmt.Errorf("bundle has no appliance entry named %s", baseName)
}

func componentRootDir(b *bundle.Bundle, component string) string {
	entries := b.Entries(component)
	if len(entries) == 0 {
		return ""
	}
	return filepath.Join(b.RootDir, component)
}

// FilterOCIImages removes dependency archives that the resolved module set
// does not need, while preserving the original relative order of everything
// else for deterministic preload behavior.
func (r Resolved) FilterOCIImages(all []images.Image) []images.Image {
	out := make([]images.Image, 0, len(all))
	for _, image := range all {
		if image.Category == images.CategoryDependency {
			if strings.HasPrefix(image.Name, "registry.local/zot@") && !r.ArtifactEnabled {
				continue
			}
			if (strings.Contains(image.Name, "/argoproj/workflow-controller:") || strings.Contains(image.Name, "/argoproj/argoexec:")) &&
				!r.WorkflowsEnabled {
				continue
			}
			if strings.HasPrefix(image.Name, "registry.local/coredns@") && !r.DNSEnabled {
				continue
			}
		}
		out = append(out, image)
	}
	return out
}

func (r Resolved) ZotComponentVersion(version string) string {
	if r.ArtifactEnabled {
		return version
	}
	return ""
}

func (r Resolved) DNSComponentVersion(version string) string {
	if r.DNSEnabled {
		return version
	}
	return ""
}
