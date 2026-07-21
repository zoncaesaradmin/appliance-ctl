package productconfig

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	ProfileCore    = "core"
	ProfileBuilder = "builder"
	ProfileStorage = "storage"
)

var supportedProfiles = map[string]struct{}{
	ProfileCore:    {},
	ProfileBuilder: {},
	ProfileStorage: {},
}

// Capability is the granular unit appliance behavior should actually be
// gated on, not the profile name itself. A profile is just a named bundle
// of capabilities; more than one profile can enable the same capability,
// so code that cares whether e.g. build/workspace support is present
// should check the capability, not compare against a specific profile
// string. This mirrors the canonical mapping in appliance-code
// (services/controlplane/internal/appliance/appliance.go's Capability
// type and profileCatalog) — kept in sync by hand, the same way
// ApplianceSharedFSGID in the hostdirs package is.
type Capability string

const (
	CapabilityBase      Capability = "base"
	CapabilityWorkflows Capability = "workflows"
	CapabilityBuild     Capability = "build"
	CapabilityArtifact  Capability = "artifact"
)

var profileCapabilities = map[string][]Capability{
	ProfileCore:    {CapabilityBase, CapabilityWorkflows},
	ProfileBuilder: {CapabilityBase, CapabilityWorkflows, CapabilityBuild, CapabilityArtifact},
	ProfileStorage: {CapabilityBase, CapabilityArtifact},
}

// HasCapability reports whether the given (already-resolved) profile
// enables capability.
func HasCapability(profile string, capability Capability) bool {
	for _, c := range profileCapabilities[profile] {
		if c == capability {
			return true
		}
	}
	return false
}

var (
	dnsLabelRE                = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	sha256ImageDigestRE       = regexp.MustCompile(`^.+@sha256:[0-9a-f]{64}$`)
	placeholderImageDigestHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	catalogNameRE             = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	ociRepoRE                 = regexp.MustCompile(`^[a-z0-9]+([._/-][a-z0-9]+)*$`)
	makeTargetRE              = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
)

func ResolveApplianceProfile(requested, current string) (string, error) {
	profile := strings.TrimSpace(requested)
	if profile == "" {
		profile = strings.TrimSpace(current)
	}
	if profile == "" {
		profile = ProfileCore
	}
	if _, ok := supportedProfiles[profile]; !ok {
		return "", fmt.Errorf("unknown appliance profile %q (supported: %s, %s, %s)", profile, ProfileCore, ProfileBuilder, ProfileStorage)
	}
	return profile, nil
}

func PrepareValuesFile(baseValuesPath, profile, buildCatalogPath, workspaceProvisionerImageReference string) (string, func(), error) {
	effectiveProfile, err := ResolveApplianceProfile(profile, "")
	if err != nil {
		return "", func() {}, err
	}
	workspaceProvisionerImageReference = strings.TrimSpace(workspaceProvisionerImageReference)
	if effectiveProfile == ProfileBuilder {
		if !validBuilderImageDigest(workspaceProvisionerImageReference) {
			return "", func() {}, fmt.Errorf("product config: builder profile requires a bundled digest-pinned workspace provisioner image reference; got %q", workspaceProvisionerImageReference)
		}
	}

	data, err := os.ReadFile(baseValuesPath)
	if err != nil {
		return "", func() {}, fmt.Errorf("product config: read values %s: %w", baseValuesPath, err)
	}

	var values map[string]any
	if err := yaml.Unmarshal(data, &values); err != nil {
		return "", func() {}, fmt.Errorf("product config: parse values %s: %w", baseValuesPath, err)
	}
	if values == nil {
		values = map[string]any{}
	}

	config, _ := values["config"].(map[string]any)
	if config == nil {
		config = map[string]any{}
	}
	config["applianceProfile"] = effectiveProfile
	if workspaceProvisionerImageReference != "" {
		config["workspaceProvisionerImageDigest"] = workspaceProvisionerImageReference
	} else {
		delete(config, "workspaceProvisionerImageDigest")
	}
	if strings.TrimSpace(buildCatalogPath) != "" {
		catalog, err := loadBuildCatalog(buildCatalogPath)
		if err != nil {
			return "", func() {}, err
		}
		config["buildCatalog"] = catalog
		config["allowedGitSourceHosts"] = deriveAllowedGitSourceHosts(catalog)
		if images := deriveAllowedBuilderImageDigests(catalog); len(images) > 0 {
			config["allowedBuilderImageDigests"] = images
		} else {
			delete(config, "allowedBuilderImageDigests")
		}
	}
	values["config"] = config

	rendered, err := yaml.Marshal(values)
	if err != nil {
		return "", func() {}, fmt.Errorf("product config: render values override: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(baseValuesPath), ".zonctl-values-*.yaml")
	if err != nil {
		return "", func() {}, fmt.Errorf("product config: create temp values file: %w", err)
	}
	if _, err := tmp.Write(rendered); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", func() {}, fmt.Errorf("product config: write temp values file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", func() {}, fmt.Errorf("product config: close temp values file: %w", err)
	}

	cleanup := func() {
		_ = os.Remove(tmp.Name())
	}
	return tmp.Name(), cleanup, nil
}

func loadBuildCatalog(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("product config: read build catalog %s: %w", path, err)
	}
	var catalog map[string]any
	if err := yaml.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("product config: parse build catalog %s: %w", path, err)
	}
	if len(catalog) == 0 {
		return nil, fmt.Errorf("product config: build catalog %s must be a non-empty object", path)
	}
	if err := flattenNestedBuildTargets(catalog, path); err != nil {
		return nil, err
	}
	normalizeCatalogExecutions(catalog)
	if err := validateBuildCatalog(catalog, path); err != nil {
		return nil, err
	}
	return catalog, nil
}

// flattenNestedBuildTargets lifts repos[].buildTargets into the top-level
// buildTargets list and fills each target's repo from its parent repo name.
func flattenNestedBuildTargets(catalog map[string]any, path string) error {
	repos := objectList(catalog["repos"])
	var lifted []any
	for repoIndex, repo := range repos {
		repoName, _ := repo["name"].(string)
		repoName = strings.TrimSpace(repoName)
		nested := objectList(repo["buildTargets"])
		if len(nested) == 0 {
			continue
		}
		if repoName == "" {
			return fmt.Errorf("product config: build catalog %s repos[%d].name is required when buildTargets are nested", path, repoIndex)
		}
		for targetIndex, target := range nested {
			copied := map[string]any{}
			for k, v := range target {
				copied[k] = v
			}
			existingRepo, _ := copied["repo"].(string)
			existingRepo = strings.TrimSpace(existingRepo)
			if existingRepo == "" {
				copied["repo"] = repoName
			} else if !strings.EqualFold(existingRepo, repoName) {
				return fmt.Errorf("product config: build catalog %s repos[%d].buildTargets[%d].repo %q does not match parent repo %q", path, repoIndex, targetIndex, existingRepo, repoName)
			} else {
				copied["repo"] = repoName
			}
			lifted = append(lifted, copied)
		}
		delete(repo, "buildTargets")
	}
	if len(lifted) == 0 {
		return nil
	}
	existing := catalog["buildTargets"]
	switch existing := existing.(type) {
	case nil:
		catalog["buildTargets"] = lifted
	case []any:
		catalog["buildTargets"] = append(append([]any{}, existing...), lifted...)
	default:
		return fmt.Errorf("product config: build catalog %s buildTargets must be a list", path)
	}
	return nil
}

func validateBuildCatalog(catalog map[string]any, path string) error {
	reposByName := map[string]struct{}{}
	repos := objectList(catalog["repos"])
	if len(repos) == 0 {
		return fmt.Errorf("product config: build catalog %s must declare at least one repos entry", path)
	}
	for _, repo := range repos {
		name, _ := repo["name"].(string)
		name = strings.TrimSpace(name)
		if name != "" {
			reposByName[name] = struct{}{}
		}
	}

	workProfiles := objectList(catalog["workProfiles"])
	if len(workProfiles) == 0 {
		return fmt.Errorf("product config: build catalog %s must declare at least one workProfiles entry", path)
	}
	for index, profile := range workProfiles {
		name, _ := profile["name"].(string)
		name = strings.TrimSpace(name)
		if name == "" {
			return fmt.Errorf("product config: build catalog %s workProfiles[%d].name is required", path, index)
		}
		profileRepos := objectList(profile["repos"])
		if len(profileRepos) == 0 {
			return fmt.Errorf("product config: build catalog %s workProfiles[%d].repos must declare at least one repo", path, index)
		}
		seenProfileRepos := map[string]struct{}{}
		for repoIndex, profileRepo := range profileRepos {
			repoName, _ := profileRepo["name"].(string)
			repoName = strings.TrimSpace(repoName)
			if repoName == "" {
				return fmt.Errorf("product config: build catalog %s workProfiles[%d].repos[%d].name is required", path, index, repoIndex)
			}
			if _, ok := reposByName[repoName]; !ok {
				return fmt.Errorf("product config: build catalog %s workProfiles[%d].repos[%d].name references unknown repo %q", path, index, repoIndex, repoName)
			}
			if _, ok := seenProfileRepos[repoName]; ok {
				return fmt.Errorf("product config: build catalog %s workProfiles[%d].repos[%d].name duplicates repo %q", path, index, repoIndex, repoName)
			}
			seenProfileRepos[repoName] = struct{}{}
		}
	}

	for index, repo := range repos {
		rawURL, _ := repo["url"].(string)
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" {
			return fmt.Errorf("product config: build catalog %s repos[%d].url is required", path, index)
		}
		u, err := url.Parse(rawURL)
		if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" {
			return fmt.Errorf("product config: build catalog %s repos[%d].url must be an https URL with a host", path, index)
		}
	}

	seenTargetNames := map[string]string{}
	for index, target := range objectList(catalog["buildTargets"]) {
		prefix := fmt.Sprintf("product config: build catalog %s buildTargets[%d]", path, index)
		name, _ := target["name"].(string)
		name = normalizeCatalogName(name)
		if name == "" {
			return fmt.Errorf("%s.name is required", prefix)
		}
		if !catalogNameRE.MatchString(name) {
			return fmt.Errorf("%s.name %q is invalid", prefix, name)
		}
		if prev, exists := seenTargetNames[name]; exists {
			return fmt.Errorf("%s.name %q duplicates build target name/alias %q", prefix, name, prev)
		}
		seenTargetNames[name] = name

		if aliases, ok := target["aliases"].([]any); ok {
			for aliasIndex, rawAlias := range aliases {
				alias, _ := rawAlias.(string)
				alias = normalizeCatalogName(alias)
				if alias == "" {
					return fmt.Errorf("%s.aliases[%d] is required when present", prefix, aliasIndex)
				}
				if !catalogNameRE.MatchString(alias) {
					return fmt.Errorf("%s.aliases[%d] %q is invalid", prefix, aliasIndex, alias)
				}
				if prev, exists := seenTargetNames[alias]; exists {
					return fmt.Errorf("%s.aliases[%d] %q duplicates build target name/alias %q", prefix, aliasIndex, alias, prev)
				}
				seenTargetNames[alias] = name
			}
		}

		repoName, _ := target["repo"].(string)
		repoName = strings.TrimSpace(repoName)
		if repoName == "" {
			return fmt.Errorf("%s.repo is required", prefix)
		}
		if _, ok := reposByName[repoName]; !ok {
			return fmt.Errorf("%s.repo references unknown repo %q", prefix, repoName)
		}

		execution, _ := target["execution"].(string)
		execution = strings.TrimSpace(execution)
		args := stringList(target["args"])
		switch execution {
		case "script":
			if len(args) != 1 {
				return fmt.Errorf("%s.args must contain exactly one script path when execution is script", prefix)
			}
			if !validRepoRelativePath(args[0]) {
				return fmt.Errorf("%s.args[0] must be a relative path inside the repo", prefix)
			}
		case "make":
			if len(args) != 1 {
				return fmt.Errorf("%s.args must contain exactly one make target when execution is make", prefix)
			}
			if !makeTargetRE.MatchString(args[0]) {
				return fmt.Errorf("%s.args[0] %q contains unsupported characters", prefix, args[0])
			}
		default:
			return fmt.Errorf("%s.execution must be make or script", prefix)
		}

		if containerfilePath, _ := target["containerfilePath"].(string); strings.TrimSpace(containerfilePath) != "" && !validRepoRelativePath(containerfilePath) {
			return fmt.Errorf("%s.containerfilePath must be a relative path inside the repo", prefix)
		}

		imageRepository, _ := target["imageRepository"].(string)
		imageRepository = strings.TrimSpace(imageRepository)
		if imageRepository == "" {
			return fmt.Errorf("%s.imageRepository is required", prefix)
		}
		if !ociRepoRE.MatchString(imageRepository) {
			return fmt.Errorf("%s.imageRepository %q is invalid", prefix, imageRepository)
		}

		builderImageDigest, _ := target["builderImageDigest"].(string)
		builderImageDigest = strings.TrimSpace(builderImageDigest)
		if builderImageDigest == "" {
			return fmt.Errorf("%s.builderImageDigest is required", prefix)
		}
		if !validBuilderImageDigest(builderImageDigest) {
			return fmt.Errorf("%s.builderImageDigest must be digest-pinned", prefix)
		}
	}

	return nil
}

func normalizeCatalogExecutions(catalog map[string]any) {
	targets := objectList(catalog["buildTargets"])
	normalized := make([]any, 0, len(targets))
	for _, target := range targets {
		normalizeTargetExecutionMap(target)
		normalized = append(normalized, target)
	}
	if len(normalized) > 0 {
		catalog["buildTargets"] = normalized
	}
}

func normalizeTargetExecutionMap(target map[string]any) {
	execution, _ := target["execution"].(string)
	execution = strings.TrimSpace(execution)
	args := stringList(target["args"])
	switch execution {
	case "make_target", "make":
		target["execution"] = "make"
		if len(args) == 0 {
			if makeTarget, _ := target["makeTarget"].(string); strings.TrimSpace(makeTarget) != "" {
				args = []string{strings.TrimSpace(makeTarget)}
			}
		}
	case "repo_script", "script":
		target["execution"] = "script"
		if len(args) == 0 {
			if scriptPath, _ := target["scriptPath"].(string); strings.TrimSpace(scriptPath) != "" {
				args = []string{strings.TrimSpace(scriptPath)}
			} else {
				args = []string{"build.sh"}
			}
		}
	}
	if len(args) > 0 {
		out := make([]any, len(args))
		for i, arg := range args {
			out[i] = arg
		}
		target["args"] = out
	}
	delete(target, "makeTarget")
	delete(target, "scriptPath")
}

func stringList(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, _ := item.(string)
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func normalizeCatalogName(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func validRepoRelativePath(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "/") || strings.Contains(v, "\\") {
		return false
	}
	clean := path.Clean(v)
	for _, part := range strings.Split(v, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func validBuilderImageDigest(image string) bool {
	image = strings.TrimSpace(image)
	if !sha256ImageDigestRE.MatchString(image) {
		return false
	}
	_, digest, _ := strings.Cut(image, "@sha256:")
	return digest != placeholderImageDigestHex
}

func deriveAllowedGitSourceHosts(catalog map[string]any) []string {
	seen := map[string]struct{}{}
	var hosts []string
	addHost := func(host string) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		if _, ok := seen[host]; ok {
			return
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}

	for _, repo := range objectList(catalog["repos"]) {
		rawURL, _ := repo["url"].(string)
		addHost(gitURLHost(rawURL))
	}
	return hosts
}

func deriveAllowedBuilderImageDigests(catalog map[string]any) []string {
	seen := map[string]struct{}{}
	var images []string
	for _, target := range objectList(catalog["buildTargets"]) {
		image, _ := target["builderImageDigest"].(string)
		image = strings.TrimSpace(image)
		if image == "" {
			continue
		}
		if _, ok := seen[image]; ok {
			continue
		}
		seen[image] = struct{}{}
		images = append(images, image)
	}
	return images
}

func gitURLHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && strings.EqualFold(u.Scheme, "https") && u.Host != "" {
		return u.Hostname()
	}
	return ""
}

func objectList(v any) []map[string]any {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if ok {
			out = append(out, m)
		}
	}
	return out
}

func validKubernetesName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, segment := range strings.Split(name, ".") {
		if len(segment) == 0 || len(segment) > 63 || !dnsLabelRE.MatchString(segment) {
			return false
		}
	}
	return true
}

func absFrom(baseDir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}
