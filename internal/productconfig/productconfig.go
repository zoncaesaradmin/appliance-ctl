package productconfig

import (
	"fmt"
	"net/url"
	"os"
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

var (
	dnsLabelRE                = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	sha256ImageDigestRE       = regexp.MustCompile(`^.+@sha256:[0-9a-f]{64}$`)
	placeholderImageDigestHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
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

func PrepareValuesFile(baseValuesPath, profile, buildCatalogPath string) (string, func(), error) {
	effectiveProfile, err := ResolveApplianceProfile(profile, "")
	if err != nil {
		return "", func() {}, err
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
	if err := validateBuildCatalog(catalog, path); err != nil {
		return nil, err
	}
	// Install-time builder catalog handling is currently workspace-first:
	// workProfiles/repos materialize source trees, while build target modeling
	// is intentionally deferred so repo cloning is not coupled to output images.
	delete(catalog, "buildTargets")
	return catalog, nil
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
	provisionerImage, _ := catalog["workspaceProvisionerImageDigest"].(string)
	if !validBuilderImageDigest(provisionerImage) {
		return fmt.Errorf("product config: build catalog %s workspaceProvisionerImageDigest must be a real sha256 image digest, not a tag or placeholder", path)
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

	return nil
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
