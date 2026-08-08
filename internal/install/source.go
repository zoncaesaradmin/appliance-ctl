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
	FilesEnabled     bool
	ArtifactEnabled  bool
	DNSEnabled       bool
	InferenceEnabled bool
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
	InferenceChartPath  string
	WorkflowsChartPath  string
	WorkflowsCRDPaths   []string
	ConfigurationPath   string
	HostAgentBinaryPath string
	HostPackagesRootDir string
	// MetadataBundleArchivePath is the signed base appliance metadata-bundle archive.
	MetadataBundleArchivePath string
	// WorkspaceProvisionerImageReference is the appliance-owned generic
	// image used by builder workspace provisioning workflows.
	WorkspaceProvisionerImageReference string
	// BuilderImageReference is an optional operator-supplied default builder
	// image digest. Builder images are not packaged in the appliance bundle;
	// catalogs must use explicit digest-pinned refs for build pods.
	BuilderImageReference string
	// HostAgentImageReference is the bundled, digest-pinned appliance host
	// agent image reference used by the host capability.
	HostAgentImageReference      string
	ArtifactServerImageReference string
	// DNSImageReference is the bundled, digest-pinned registry.local/coredns
	// image reference used for the landns/storage-landns capability.
	DNSImageReference string
	// InferenceImageReference is the bundled, digest-pinned
	// registry.local/inference-runtime image reference used for the
	// inference capability.
	InferenceImageReference string

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
	// PackDirs are additional signed pack bundle directories (developer,
	// inference) verified with the same public key and merged into Resolved.
	PackDirs  []string
	PublicKey *verify.PublicKey
}

func (s OfflineSource) Resolve(ctx context.Context, requestedProfile string) (Resolved, []evidence.Check, error) {
	_ = ctx
	b, checks, err := bundle.Load(s.BundleDir, s.PublicKey)
	if err != nil {
		return Resolved{}, checks, fmt.Errorf("install: %w", err)
	}
	var packs []*bundle.Bundle
	for _, dir := range s.PackDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		pb, packChecks, packErr := bundle.Load(dir, s.PublicKey)
		checks = append(checks, packChecks...)
		if packErr != nil {
			return Resolved{}, checks, fmt.Errorf("install: pack-dir %s: %w", dir, packErr)
		}
		packs = append(packs, pb)
	}
	view := mergedBundle{primary: b, packs: packs}
	compat := mergeCompatibility(b, packs)

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
	filesEnabled := productconfig.ModuleEnabled(resolvedModules, productconfig.ModuleNameFiles)
	dnsEnabled := productconfig.ModuleEnabled(resolvedModules, productconfig.ModuleNameLANDNS)
	inferenceEnabled := productconfig.ModuleEnabled(resolvedModules, productconfig.ModuleNameInferenceRuntime)
	buildEnabled := productconfig.ModuleEnabled(resolvedModules, productconfig.ModuleNameBuild)
	workflowsEnabled := productconfig.HasCapabilityInCatalog(effectiveProfile, productconfig.CapabilityWorkflows, catalog.Profiles)

	workflowsChartPath := ""
	workflowsCRDPaths := []string(nil)
	if workflowsEnabled || buildEnabled {
		workflowsChartPath = optionalWorkflowsChartPath(view)
		workflowsCRDPaths = crdPaths(view)
		if workflowsChartPath == "" && len(workflowsCRDPaths) == 0 {
			return Resolved{}, checks, fmt.Errorf("install: profile %q requires workflows/build capability but the developer pack was not provided (missing workflows chart and/or CRDs)", effectiveProfile)
		}
		if workflowsChartPath != "" && len(workflowsCRDPaths) == 0 {
			return Resolved{}, checks, fmt.Errorf("install: bundle has a workflows chart but no workflows-crds artifact; the workflow controller cannot start without its CRDs")
		}
		if workflowsChartPath == "" {
			return Resolved{}, checks, fmt.Errorf("install: profile %q requires workflows/build capability but the developer pack was not provided (missing workflows chart)", effectiveProfile)
		}
	}
	registryChartPath := ""
	if artifactEnabled && strings.TrimSpace(compat.ArtifactServerVersion) != "" {
		registryChartPath, err = requiredRegistryChartPath(view)
		if err != nil {
			return Resolved{}, checks, fmt.Errorf("install: %w", err)
		}
	}
	dnsChartPath := ""
	if dnsEnabled && strings.TrimSpace(compat.DNSVersion) != "" {
		dnsChartPath, err = requiredDNSChartPath(view)
		if err != nil {
			return Resolved{}, checks, fmt.Errorf("install: %w", err)
		}
	}
	inferenceChartPath := ""
	if inferenceEnabled && strings.TrimSpace(compat.InferenceVersion) != "" {
		inferenceChartPath, err = requiredInferenceChartPath(view)
		if err != nil {
			return Resolved{}, checks, fmt.Errorf("install: profile %q requires inference capability but the inference pack was not provided: %w", effectiveProfile, err)
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
	if hostPackagesRootDir == "" {
		return Resolved{}, checks, fmt.Errorf("install: signed bundle is missing required host-packages (mdns + wifi-ap offline debs for day-2 enablement)")
	}
	metadataBundleArchivePath, err := requiredMetadataBundleArchivePath(b)
	if err != nil {
		return Resolved{}, checks, fmt.Errorf("install: %w", err)
	}

	var k3sImages, ociImages []images.Image
	for _, e := range b.Entries("k3s-images") {
		name, requireReference := imageName(e)
		k3sImages = append(k3sImages, images.Image{Name: name, ArchivePath: e.Path, ExpectedDigest: e.Digest, Category: images.CategoryK3sPlatform, RequireReference: requireReference})
	}
	for _, e := range view.Entries("oci-images") {
		name, requireReference := imageName(e)
		category := images.CategoryApplication
		if isArtifactServerImageReference(e.ImageReference) || isDNSImageReference(e.ImageReference) || isInferenceRuntimeImageReference(e.ImageReference) || isWorkflowDependencyReference(e.ImageReference) {
			category = images.CategoryDependency
		}
		ociImages = append(ociImages, images.Image{Name: name, ArchivePath: e.Path, ExpectedDigest: e.Digest, Category: category, RequireReference: requireReference})
	}
	workspaceProvisionerImageReference := workspaceProvisionerImageReference(view)
	builderImageReference := builderImageReference(view)
	hostAgentImageReference := ""
	if hostEnabled {
		hostAgentImageReference, err = requiredHostAgentImageReference(view)
		if err != nil {
			return Resolved{}, checks, fmt.Errorf("install: %w", err)
		}
	}
	artifactServerImageReference := ""
	if artifactEnabled && strings.TrimSpace(compat.ArtifactServerVersion) != "" {
		artifactServerImageReference, err = requiredArtifactServerImageReference(view)
		if err != nil {
			return Resolved{}, checks, fmt.Errorf("install: %w", err)
		}
	}
	dnsImageReference := ""
	if dnsEnabled && strings.TrimSpace(compat.DNSVersion) != "" {
		dnsImageReference, err = requiredDNSImageReference(view)
		if err != nil {
			return Resolved{}, checks, fmt.Errorf("install: %w", err)
		}
	}
	inferenceImageReference := ""
	if inferenceEnabled && strings.TrimSpace(compat.InferenceVersion) != "" {
		inferenceImageReference, err = requiredInferenceImageReference(view)
		if err != nil {
			return Resolved{}, checks, fmt.Errorf("install: profile %q requires inference capability but the inference pack was not provided: %w", effectiveProfile, err)
		}
	}

	return Resolved{
		BundleVersion:                      b.BundleVersion,
		ReleaseID:                          b.ReleaseID,
		HostBaseline:                       b.HostBaseline,
		Compatibility:                      compat,
		EffectiveProfile:                   effectiveProfile,
		CatalogPath:                        catalogPath,
		HostEnabled:                        hostEnabled,
		FilesEnabled:                       filesEnabled,
		ArtifactEnabled:                    artifactEnabled,
		DNSEnabled:                         dnsEnabled,
		InferenceEnabled:                   inferenceEnabled,
		BuildEnabled:                       buildEnabled,
		WorkflowsEnabled:                   workflowsEnabled,
		ZonctlBinaryPath:                   zonctlBinaryPath,
		HelperBinaryPaths:                  helperBinaryPaths,
		K3sBinaryPath:                      k3sBinaryPath,
		ChartPath:                          chartPath,
		RegistryChartPath:                  registryChartPath,
		DNSChartPath:                       dnsChartPath,
		InferenceChartPath:                 inferenceChartPath,
		WorkflowsChartPath:                 workflowsChartPath,
		WorkflowsCRDPaths:                  workflowsCRDPaths,
		ConfigurationPath:                  configurationPath,
		HostAgentBinaryPath:                hostAgentBinaryPath,
		HostPackagesRootDir:                hostPackagesRootDir,
		MetadataBundleArchivePath:          metadataBundleArchivePath,
		WorkspaceProvisionerImageReference: workspaceProvisionerImageReference,
		BuilderImageReference:              builderImageReference,
		HostAgentImageReference:            hostAgentImageReference,
		ArtifactServerImageReference:       artifactServerImageReference,
		DNSImageReference:                  dnsImageReference,
		InferenceImageReference:            inferenceImageReference,
		K3sImages:                          k3sImages,
		OCIImages:                          ociImages,
	}, checks, nil
}

// entrySource is anything that can list verified bundle entries by component.
type entrySource interface {
	Entries(component string) []bundle.Entry
}

// mergedBundle presents primary + pack entries as one lookup surface for
// charts, CRDs, and OCI images while keeping base-only artifacts on primary.
type mergedBundle struct {
	primary *bundle.Bundle
	packs   []*bundle.Bundle
}

func (m mergedBundle) Entries(component string) []bundle.Entry {
	out := append([]bundle.Entry{}, m.primary.Entries(component)...)
	for _, p := range m.packs {
		out = append(out, p.Entries(component)...)
	}
	return out
}

func mergeCompatibility(primary *bundle.Bundle, packs []*bundle.Bundle) bundle.Compatibility {
	compat := primary.Compatibility
	for _, p := range packs {
		if strings.TrimSpace(compat.WorkflowsVersion) == "" {
			compat.WorkflowsVersion = p.Compatibility.WorkflowsVersion
		}
		if strings.TrimSpace(compat.InferenceVersion) == "" {
			compat.InferenceVersion = p.Compatibility.InferenceVersion
		}
		if strings.TrimSpace(compat.ArtifactServerVersion) == "" {
			compat.ArtifactServerVersion = p.Compatibility.ArtifactServerVersion
		}
		if strings.TrimSpace(compat.DNSVersion) == "" {
			compat.DNSVersion = p.Compatibility.DNSVersion
		}
	}
	return compat
}

func isArtifactServerImageReference(ref string) bool {
	return strings.HasPrefix(strings.TrimSpace(ref), "registry.local/artifact-server@sha256:")
}

func isDNSImageReference(ref string) bool {
	return strings.HasPrefix(strings.TrimSpace(ref), "registry.local/coredns@sha256:")
}

func isInferenceRuntimeImageReference(ref string) bool {
	return strings.HasPrefix(strings.TrimSpace(ref), "registry.local/inference-runtime@sha256:")
}

func isWorkflowDependencyReference(ref string) bool {
	ref = strings.TrimSpace(ref)
	return strings.Contains(ref, "/argoproj/workflow-controller:") ||
		strings.Contains(ref, "/appliance-workflow-controller:") ||
		strings.Contains(ref, "/argoproj/argoexec:")
}

func isHostAgentImageReference(ref string) bool {
	return strings.HasPrefix(strings.TrimSpace(ref), "registry.local/appliance-host-agent@sha256:")
}

func requiredHostAgentImageReference(b entrySource) (string, error) {
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

func requiredArtifactServerImageReference(b entrySource) (string, error) {
	var found string
	for _, e := range b.Entries("oci-images") {
		if !isArtifactServerImageReference(e.ImageReference) {
			continue
		}
		if found != "" {
			return "", fmt.Errorf("bundle has multiple artifact server image entries")
		}
		found = strings.TrimSpace(e.ImageReference)
	}
	if found == "" {
		return "", fmt.Errorf("bundle has no canonical registry.local/artifact-server@sha256 image entry")
	}
	return found, nil
}

func requiredDNSImageReference(b entrySource) (string, error) {
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

func requiredInferenceImageReference(b entrySource) (string, error) {
	var found string
	for _, e := range b.Entries("oci-images") {
		if !isInferenceRuntimeImageReference(e.ImageReference) {
			continue
		}
		if found != "" {
			return "", fmt.Errorf("bundle has multiple inference-runtime image entries")
		}
		found = strings.TrimSpace(e.ImageReference)
	}
	if found == "" {
		return "", fmt.Errorf("bundle has no canonical registry.local/inference-runtime@sha256 image entry")
	}
	return found, nil
}

func imageName(e bundle.Entry) (string, bool) {
	if e.ImageReference != "" {
		return e.ImageReference, true
	}
	return e.Path, false
}

func workspaceProvisionerImageReference(b entrySource) string {
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

func builderImageReference(b entrySource) string {
	// Builder images are operator-supplied and are not packaged in the product
	// bundle. Keep a best-effort lookup for any day-2 injected digest entry, but
	// do not require registry.local/dev-build.
	for _, e := range b.Entries("oci-images") {
		ref := strings.TrimSpace(e.ImageReference)
		if ref == "" || !strings.Contains(ref, "@sha256:") {
			continue
		}
		if strings.Contains(ref, "/dev-build@sha256:") ||
			strings.HasPrefix(ref, "dev-build@sha256:") {
			return ref
		}
	}
	return ""
}

func applianceChartPath(b entrySource) (string, error) {
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

func optionalWorkflowsChartPath(b entrySource) string {
	for _, e := range b.Entries("chart") {
		base := strings.ToLower(filepath.Base(e.Path))
		if strings.Contains(base, "workflows-chart") || strings.Contains(base, "appliance-workflows") {
			return e.Path
		}
	}
	return ""
}

func requiredRegistryChartPath(b entrySource) (string, error) {
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

func requiredDNSChartPath(b entrySource) (string, error) {
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

func requiredInferenceChartPath(b entrySource) (string, error) {
	var found string
	for _, e := range b.Entries("chart") {
		base := strings.ToLower(filepath.Base(e.Path))
		if !strings.HasPrefix(base, "appliance-inference-") {
			continue
		}
		if found != "" {
			return "", fmt.Errorf("bundle has multiple appliance-inference chart entries")
		}
		found = e.Path
	}
	if found == "" {
		return "", fmt.Errorf("bundle has no appliance-inference chart entry")
	}
	return found, nil
}

func crdPaths(b entrySource) []string {
	entries := b.Entries("kubernetes-crds")
	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		paths = append(paths, e.Path)
	}
	sort.Strings(paths)
	return paths
}

func requiredMetadataBundleArchivePath(b entrySource) (string, error) {
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

func configurationPath(b entrySource) (string, error) {
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

func optionalCatalogPath(b entrySource) (string, error) {
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

func applianceBinaryPath(b entrySource, baseName string) (string, error) {
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
		if strings.HasPrefix(image.Name, "registry.local/workspace-provisioner@") && !r.BuildEnabled {
			continue
		}
		if image.Category == images.CategoryDependency {
			if strings.HasPrefix(image.Name, "registry.local/artifact-server@") && !r.ArtifactEnabled {
				continue
			}
			if (strings.Contains(image.Name, "/argoproj/workflow-controller:") ||
				strings.Contains(image.Name, "/appliance-workflow-controller:") ||
				strings.Contains(image.Name, "/argoproj/argoexec:")) &&
				!r.WorkflowsEnabled {
				continue
			}
			if strings.HasPrefix(image.Name, "registry.local/coredns@") && !r.DNSEnabled {
				continue
			}
			if strings.HasPrefix(image.Name, "registry.local/inference-runtime@") && !r.InferenceEnabled {
				continue
			}
		}
		out = append(out, image)
	}
	return out
}

func (r Resolved) ArtifactServerComponentVersion(version string) string {
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

func (r Resolved) InferenceComponentVersion(version string) string {
	if r.InferenceEnabled {
		return version
	}
	return ""
}
