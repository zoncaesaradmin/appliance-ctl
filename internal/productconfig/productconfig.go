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

var dnsLabelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

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
		config["allowedBuilderImageDigests"] = deriveAllowedBuilderImageDigests(catalog)
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

func ValidateSourceCredentialProvisioning(buildCatalogPath string, provisioned []SourceCredentialSecret) error {
	if strings.TrimSpace(buildCatalogPath) == "" {
		return nil
	}
	catalog, err := loadBuildCatalog(buildCatalogPath)
	if err != nil {
		return err
	}
	required := sourceCredentialSecretNames(catalog)
	if len(required) == 0 {
		return nil
	}
	if len(provisioned) == 0 {
		return fmt.Errorf("product config: build catalog %s declares sourceCredentials; --source-credentials is required to provision matching Kubernetes Secrets", buildCatalogPath)
	}
	provisionedNames := map[string]struct{}{}
	for _, cred := range provisioned {
		if cred.SecretName != "" {
			provisionedNames[cred.SecretName] = struct{}{}
		}
		if cred.KnownHostsSecretName != "" {
			provisionedNames[cred.KnownHostsSecretName] = struct{}{}
		}
	}
	for _, name := range required {
		if _, ok := provisionedNames[name]; !ok {
			return fmt.Errorf("product config: build catalog %s requires source credential Secret %q, but it is not provisioned by --source-credentials", buildCatalogPath, name)
		}
	}
	return nil
}

func sourceCredentialSecretNames(catalog map[string]any) []string {
	seen := map[string]struct{}{}
	var names []string
	add := func(value any) {
		name, _ := value.(string)
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	for _, credential := range objectList(catalog["sourceCredentials"]) {
		add(credential["kubernetesSecretName"])
		add(credential["knownHostsSecretName"])
	}
	return names
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
	return catalog, nil
}

func validateBuildCatalog(catalog map[string]any, path string) error {
	targets := objectList(catalog["buildTargets"])
	if len(targets) == 0 {
		return fmt.Errorf("product config: build catalog %s must declare at least one buildTargets entry", path)
	}

	reposByName := map[string]struct{}{}
	for _, repo := range objectList(catalog["repos"]) {
		name, _ := repo["name"].(string)
		name = strings.TrimSpace(name)
		if name != "" {
			reposByName[name] = struct{}{}
		}
	}

	credentialsByID := map[string]map[string]any{}
	for index, credential := range objectList(catalog["sourceCredentials"]) {
		id, _ := credential["id"].(string)
		id = strings.TrimSpace(id)
		if id == "" {
			return fmt.Errorf("product config: build catalog %s sourceCredentials[%d].id is required", path, index)
		}
		if _, ok := credential["gitHost"].(string); !ok || strings.TrimSpace(fmt.Sprint(credential["gitHost"])) == "" {
			return fmt.Errorf("product config: build catalog %s sourceCredentials[%d].gitHost is required", path, index)
		}
		if _, ok := credential["kubernetesSecretName"].(string); !ok || strings.TrimSpace(fmt.Sprint(credential["kubernetesSecretName"])) == "" {
			return fmt.Errorf("product config: build catalog %s sourceCredentials[%d].kubernetesSecretName is required", path, index)
		}
		credentialsByID[id] = credential
	}

	for index, repo := range objectList(catalog["repos"]) {
		rawURL, _ := repo["url"].(string)
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" {
			return fmt.Errorf("product config: build catalog %s repos[%d].url is required", path, index)
		}
		if !isSSHGitURL(rawURL) {
			continue
		}
		ref, _ := repo["sourceCredentialRef"].(string)
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return fmt.Errorf("product config: build catalog %s repos[%d].sourceCredentialRef is required for SSH repo URLs", path, index)
		}
		credential, ok := credentialsByID[ref]
		if !ok {
			return fmt.Errorf("product config: build catalog %s repos[%d].sourceCredentialRef references unknown sourceCredentials entry %q", path, index, ref)
		}
		knownHostsSecretName, _ := credential["knownHostsSecretName"].(string)
		if strings.TrimSpace(knownHostsSecretName) == "" {
			return fmt.Errorf("product config: build catalog %s repos[%d].sourceCredentialRef uses SSH but sourceCredentials %q has no knownHostsSecretName", path, index, ref)
		}
	}

	for index, target := range targets {
		for _, key := range []string{"name", "repo", "execution", "imageRepository", "builderImageDigest"} {
			value, _ := target[key].(string)
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("product config: build catalog %s buildTargets[%d].%s is required", path, index, key)
			}
		}
		repo, _ := target["repo"].(string)
		if _, ok := reposByName[strings.TrimSpace(repo)]; !ok {
			return fmt.Errorf("product config: build catalog %s buildTargets[%d].repo references unknown repo %q", path, index, repo)
		}
		execution, _ := target["execution"].(string)
		if execution != "repo_script" && execution != "make_target" {
			return fmt.Errorf("product config: build catalog %s buildTargets[%d].execution must be repo_script or make_target", path, index)
		}
		builderImageDigest, _ := target["builderImageDigest"].(string)
		if !strings.Contains(builderImageDigest, "@sha256:") {
			return fmt.Errorf("product config: build catalog %s buildTargets[%d].builderImageDigest must include @sha256:", path, index)
		}
	}

	return nil
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

	for _, credential := range objectList(catalog["sourceCredentials"]) {
		host, _ := credential["gitHost"].(string)
		addHost(host)
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
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Hostname()
	}
	if before, _, ok := strings.Cut(raw, ":"); ok && !strings.Contains(before, "/") {
		if _, host, ok := strings.Cut(before, "@"); ok {
			return host
		}
	}
	return ""
}

func isSSHGitURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	return strings.HasPrefix(raw, "git@") || strings.HasPrefix(raw, "ssh://")
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

// SourceCredentialSecret is operator-local install/upgrade input used to
// materialize Git source credential files into Kubernetes Secrets. It carries
// file paths and Secret names only; key material stays in the referenced files
// and must never be placed in build catalogs or release bundles.
type SourceCredentialSecret struct {
	Namespace            string `yaml:"namespace" json:"namespace"`
	SecretName           string `yaml:"secretName" json:"secretName"`
	PrivateKeyPath       string `yaml:"privateKeyPath" json:"privateKeyPath"`
	KnownHostsSecretName string `yaml:"knownHostsSecretName" json:"knownHostsSecretName"`
	KnownHostsPath       string `yaml:"knownHostsPath" json:"knownHostsPath"`
}

type sourceCredentialsDoc struct {
	Credentials []SourceCredentialSecret `yaml:"credentials" json:"credentials"`
}

func LoadSourceCredentialSecrets(path, defaultNamespace string) ([]SourceCredentialSecret, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("product config: read source credentials %s: %w", path, err)
	}
	var doc sourceCredentialsDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("product config: parse source credentials %s: %w", path, err)
	}
	if len(doc.Credentials) == 0 {
		return nil, fmt.Errorf("product config: source credentials %s must contain credentials", path)
	}
	baseDir := filepath.Dir(path)
	for i := range doc.Credentials {
		cred := &doc.Credentials[i]
		cred.Namespace = strings.TrimSpace(cred.Namespace)
		if cred.Namespace == "" {
			cred.Namespace = defaultNamespace
		}
		cred.SecretName = strings.TrimSpace(cred.SecretName)
		cred.PrivateKeyPath = absFrom(baseDir, strings.TrimSpace(cred.PrivateKeyPath))
		cred.KnownHostsSecretName = strings.TrimSpace(cred.KnownHostsSecretName)
		cred.KnownHostsPath = absFrom(baseDir, strings.TrimSpace(cred.KnownHostsPath))
		if cred.Namespace == "" || cred.SecretName == "" || cred.PrivateKeyPath == "" {
			return nil, fmt.Errorf("product config: source credential entry %d requires namespace, secretName, and privateKeyPath", i)
		}
		if !validKubernetesName(cred.Namespace) {
			return nil, fmt.Errorf("product config: source credential entry %d has invalid namespace %q", i, cred.Namespace)
		}
		if !validKubernetesName(cred.SecretName) {
			return nil, fmt.Errorf("product config: source credential entry %d has invalid secretName %q", i, cred.SecretName)
		}
		if cred.KnownHostsSecretName != "" && cred.KnownHostsPath == "" {
			return nil, fmt.Errorf("product config: source credential entry %d has knownHostsSecretName but no knownHostsPath", i)
		}
		if cred.KnownHostsPath != "" && cred.KnownHostsSecretName == "" {
			return nil, fmt.Errorf("product config: source credential entry %d has knownHostsPath but no knownHostsSecretName", i)
		}
		if cred.KnownHostsSecretName != "" && !validKubernetesName(cred.KnownHostsSecretName) {
			return nil, fmt.Errorf("product config: source credential entry %d has invalid knownHostsSecretName %q", i, cred.KnownHostsSecretName)
		}
	}
	return doc.Credentials, nil
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
