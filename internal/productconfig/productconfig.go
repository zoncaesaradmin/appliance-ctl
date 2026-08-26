package productconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	ProfileCore                       = "core"
	ProfileBuilder                    = "builder"
	ProfileStorage                    = "storage"
	ProfileLANDNS                     = "landns"
	ProfileStorageLANDNS              = "storage-landns"
	ProfileBuilderLANDNS              = "builder-landns"
	ProfileBuilderStorageLANDNS       = "builder-storage-landns"
	ProfileLANLLM                     = "lanllm"
	ProfileBuilderLANLLM              = "builder-lanllm"
	ProfileBuilderLANLLMStorageLANDNS = "builder-lanllm-storage-landns"
	ProfileTraining                   = "training"

	// ControlPlaneAppsNamespace hosts ui-server, host-agent, and
	// automation-runtime. controlplane itself uses defaultChartNamespace
	// (ace-system).
	ControlPlaneAppsNamespace = "ace-apps"
	// ApplicationNamespace is permanently provisioned for user-managed
	// application workloads and is independent from co-packaged services.
	ApplicationNamespace = "apps"

	// Fixed product namespaces for capability-scoped charts (in addition to
	// the control-plane release namespace and ControlPlaneAppsNamespace).
	ArtifactsNamespace = "artifacts"
	DNSNamespace       = "dns"
	InferenceNamespace = "inference"
	// WorkflowsControllerNamespace hosts the workflow-controller release.
	WorkflowsControllerNamespace = "workflows"
	// WorkflowsBuildNamespace hosts build/workspace PVCs, workflow jobs, and
	// related control-plane RBAC for appliance-managed workflows.
	WorkflowsBuildNamespace = "appliance-builds"

	// ImagePullSecretName mirrors helm.ImagePullSecretName for chart values
	// injection. Secrets are namespaced; when lab image-pull is configured,
	// zonctl places this secret in every product namespace (not kube-system).
	ImagePullSecretName = "appliance-image-pull"
)

// ProductNamespaces returns every appliance-owned namespace that may run product
// pods. controlPlaneNS is the chart release namespace for controlplane and the
// message broker (default ace-system). kube-system and other K3s system
// namespaces are intentionally excluded.
func ProductNamespaces(controlPlaneNS string) []string {
	controlPlaneNS = strings.TrimSpace(controlPlaneNS)
	if controlPlaneNS == "" {
		controlPlaneNS = "ace-system"
	}
	return []string{
		controlPlaneNS,
		ControlPlaneAppsNamespace,
		ApplicationNamespace,
		ArtifactsNamespace,
		DNSNamespace,
		InferenceNamespace,
		WorkflowsControllerNamespace,
		WorkflowsBuildNamespace,
	}
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
	CapabilityBase         Capability = "base"
	CapabilityHost         Capability = "host"
	CapabilityWorkflows    Capability = "workflows"
	CapabilityBuild        Capability = "build"
	CapabilityFiles        Capability = "files"
	CapabilityArtifact     Capability = "artifact"
	CapabilityDNS          Capability = "dns"
	CapabilityInference    Capability = "inference"
	CapabilityVideo        Capability = "video"
	CapabilityApplications Capability = "applications"
)

type ProfileDefinition struct {
	Capabilities []Capability
}

type ProfileCatalog map[string]ProfileDefinition

var builtInProfileCatalog = ProfileCatalog{
	// Keep in sync with appliance-code metadata-bundle/base/profiles/catalog.yaml
	// for shared profile names. Pack derivation uses capabilities, not profile names.
	ProfileCore:                       {Capabilities: []Capability{CapabilityBase, CapabilityFiles}},
	ProfileBuilder:                    {Capabilities: []Capability{CapabilityBase, CapabilityHost, CapabilityFiles, CapabilityWorkflows, CapabilityBuild, CapabilityArtifact}},
	ProfileStorage:                    {Capabilities: []Capability{CapabilityBase, CapabilityHost, CapabilityFiles, CapabilityArtifact}},
	ProfileLANDNS:                     {Capabilities: []Capability{CapabilityBase, CapabilityHost, CapabilityFiles, CapabilityDNS}},
	ProfileStorageLANDNS:              {Capabilities: []Capability{CapabilityBase, CapabilityHost, CapabilityFiles, CapabilityArtifact, CapabilityDNS}},
	ProfileBuilderLANDNS:              {Capabilities: []Capability{CapabilityBase, CapabilityHost, CapabilityFiles, CapabilityWorkflows, CapabilityBuild, CapabilityArtifact, CapabilityDNS}},
	ProfileBuilderStorageLANDNS:       {Capabilities: []Capability{CapabilityBase, CapabilityHost, CapabilityFiles, CapabilityWorkflows, CapabilityBuild, CapabilityArtifact, CapabilityDNS}},
	ProfileLANLLM:                     {Capabilities: []Capability{CapabilityBase, CapabilityInference}},
	ProfileBuilderLANLLM:              {Capabilities: []Capability{CapabilityBase, CapabilityHost, CapabilityFiles, CapabilityWorkflows, CapabilityBuild, CapabilityArtifact, CapabilityInference}},
	ProfileBuilderLANLLMStorageLANDNS: {Capabilities: []Capability{CapabilityBase, CapabilityHost, CapabilityFiles, CapabilityWorkflows, CapabilityBuild, CapabilityArtifact, CapabilityDNS, CapabilityInference}},
	ProfileTraining:                   {Capabilities: []Capability{CapabilityBase, CapabilityFiles, CapabilityVideo}},
}

var builtInProfileOrder = []string{
	ProfileCore,
	ProfileBuilder,
	ProfileStorage,
	ProfileLANDNS,
	ProfileStorageLANDNS,
	ProfileBuilderLANDNS,
	ProfileBuilderStorageLANDNS,
	ProfileLANLLM,
	ProfileBuilderLANLLM,
	ProfileBuilderLANLLMStorageLANDNS,
	ProfileTraining,
}

func BuiltInProfileCatalog() ProfileCatalog {
	return cloneProfileCatalog(builtInProfileCatalog)
}

const (
	DefaultArtifactServerBaseURL   = "http://appliance-registry.artifacts.svc.cluster.local:5000"
	DefaultRegistryPublicKeySecret = "appliance-registry-verification-key"
	// WifiAPManagementAddress is always injected as a TLS SAN.
	WifiAPManagementAddress = "10.42.0.1"
	// WifiAPManagementHostname is always injected as a TLS SAN for
	// https://manage.ap/ on the management Wi-Fi access point.
	WifiAPManagementHostname = "manage.ap"
	// DefaultDNSReadyURL is the CoreDNS health-plugin readiness endpoint
	// the control plane polls to gate any dns-capability-dependent
	// behavior on the LAN DNS release actually being up, mirroring how
	// artifactServerBaseURL gates artifact-capability behavior on the registry
	// release.
	// CoreDNS ready plugin listens on :8181 (/ready); health is :8080 (/health).
	DefaultDNSReadyURL = "http://dns-server.dns.svc.cluster.local:8181/ready"
	// DefaultInferenceGatewayBaseURL is the in-cluster OpenAI-compatible
	// gateway Service used when the inference capability is enabled. The
	// control plane authenticates and reverse-proxies /inference/v1/* here.
	DefaultInferenceGatewayBaseURL = "http://inference-gateway.inference.svc.cluster.local:8080"
	// DefaultLANDNSZone is the CoreDNS local-zone suffix for LAN A records.
	// Must not be ".local" — systemd-resolved (and dig) treat .local as
	// Multicast DNS and will never send those queries to unicast DNS.
	DefaultLANDNSZone = "appliance.internal"
)

// RequiredPacks returns the optional signed pack IDs needed for profile
// beyond the foundation pack. The foundation pack is always required conceptually and
// is not listed here.
func RequiredPacks(profile string) []string {
	var packs []string
	if HasCapability(profile, CapabilityWorkflows) || HasCapability(profile, CapabilityBuild) ||
		HasCapability(profile, CapabilityArtifact) || HasCapability(profile, CapabilityDNS) {
		packs = append(packs, "developer")
	}
	if HasCapability(profile, CapabilityHost) {
		packs = append(packs, "deviceuser")
	}
	if HasCapability(profile, CapabilityInference) {
		packs = append(packs, "inference")
	}
	return packs
}

// HasCapability reports whether the given (already-resolved) profile
// enables capability.
func HasCapability(profile string, capability Capability) bool {
	return HasCapabilityInCatalog(profile, capability, builtInProfileCatalog)
}

func HasCapabilityInCatalog(profile string, capability Capability, catalog ProfileCatalog) bool {
	for _, c := range capabilitiesForProfileInCatalog(profile, catalog) {
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
)

func ResolveApplianceProfile(requested, current string) (string, error) {
	return ResolveApplianceProfileWithCatalog(requested, current, builtInProfileCatalog)
}

func ResolveApplianceProfileWithCatalog(requested, current string, catalog ProfileCatalog) (string, error) {
	profile := strings.TrimSpace(requested)
	if profile == "" {
		profile = strings.TrimSpace(current)
	}
	if profile == "" {
		profile = ProfileCore
	}
	if _, ok := catalog[profile]; !ok {
		return "", fmt.Errorf("unknown appliance profile %q (supported: %s)", profile, strings.Join(builtInProfileOrder, ", "))
	}
	return profile, nil
}

func capabilitiesForProfile(profile string) []Capability {
	return capabilitiesForProfileInCatalog(profile, builtInProfileCatalog)
}

func capabilitiesForProfileInCatalog(profile string, catalog ProfileCatalog) []Capability {
	definition, ok := catalog[strings.TrimSpace(profile)]
	if !ok {
		return nil
	}
	return append([]Capability(nil), definition.Capabilities...)
}

func cloneProfileCatalog(catalog ProfileCatalog) ProfileCatalog {
	cloned := make(ProfileCatalog, len(catalog))
	for profile, definition := range catalog {
		cloned[profile] = ProfileDefinition{
			Capabilities: append([]Capability(nil), definition.Capabilities...),
		}
	}
	return cloned
}

// ApplianceIdentity is the product LAN name for one appliance instance.
// FQDN is always {Name}.{Zone}; there is no separate public_host override.
type ApplianceIdentity struct {
	Name string
	Zone string
	FQDN string
}

// NormalizeApplianceName validates a single DNS label used as the appliance
// instance name (not the OS hostname).
func NormalizeApplianceName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "ns" || !dnsLabelRE.MatchString(name) {
		return "", fmt.Errorf("product config: appliance name %q must be a single DNS label (a-z0-9 and hyphens)", name)
	}
	return name, nil
}

// NormalizeDNSZone validates the LAN DNS zone. Empty defaults to
// DefaultLANDNSZone. The .local TLD is rejected (mDNS-only on Ubuntu).
func NormalizeDNSZone(zone string) (string, error) {
	zone = strings.ToLower(strings.TrimSpace(zone))
	zone = strings.TrimSuffix(zone, ".")
	if zone == "" {
		zone = DefaultLANDNSZone
	}
	if zone == "local" || strings.HasSuffix(zone, ".local") {
		return "", fmt.Errorf("product config: dns zone %q must not use .local (reserved for mDNS)", zone)
	}
	labels := strings.Split(zone, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("product config: dns zone %q must contain at least two labels", zone)
	}
	for _, label := range labels {
		if !dnsLabelRE.MatchString(label) {
			return "", fmt.Errorf("product config: dns zone %q has invalid label %q", zone, label)
		}
	}
	return zone, nil
}

// ResolveApplianceIdentity validates name+zone and returns the derived FQDN.
func ResolveApplianceIdentity(name, zone string) (ApplianceIdentity, error) {
	normalizedName, err := NormalizeApplianceName(name)
	if err != nil {
		return ApplianceIdentity{}, err
	}
	normalizedZone, err := NormalizeDNSZone(zone)
	if err != nil {
		return ApplianceIdentity{}, err
	}
	return ApplianceIdentity{
		Name: normalizedName,
		Zone: normalizedZone,
		FQDN: normalizedName + "." + normalizedZone,
	}, nil
}

func PrepareValuesFile(baseValuesPath, profile, applianceCatalogPath, workspaceProvisionerImageReference, builderImageReference, hostAgentImageReference, applianceName, dnsZone, nodeIPv4 string, registry ...string) (string, func(), error) {
	catalog, err := LoadCatalog(applianceCatalogPath)
	if err != nil {
		return "", func() {}, err
	}

	effectiveProfile, err := ResolveApplianceProfileWithCatalog(profile, "", catalog.Profiles)
	if err != nil {
		return "", func() {}, err
	}
	resolvedModules := ResolveModulesWithCatalog(effectiveProfile, catalog.Profiles, AlwaysEntitled{}, catalog.Modules)
	hostAgentEnabled := HostAgentEnabled(resolvedModules)
	artifactEnabled := ModuleEnabled(resolvedModules, ModuleNameArtifactRegistry)
	dnsEnabled := ModuleEnabled(resolvedModules, ModuleNameLANDNS)
	inferenceEnabled := ModuleEnabled(resolvedModules, ModuleNameInferenceRuntime)
	buildEnabled := ModuleEnabled(resolvedModules, ModuleNameBuild)
	identity, err := ResolveApplianceIdentity(applianceName, dnsZone)
	if err != nil {
		return "", func() {}, err
	}
	workspaceProvisionerImageReference = strings.TrimSpace(workspaceProvisionerImageReference)
	builderImageReference = strings.TrimSpace(builderImageReference)
	hostAgentImageReference = strings.TrimSpace(hostAgentImageReference)
	artifactServerImageReference := ""
	blobStorageImageReference := ""
	if len(registry) > 0 {
		artifactServerImageReference = strings.TrimSpace(registry[0])
	}
	if len(registry) > 1 {
		blobStorageImageReference = strings.TrimSpace(registry[1])
	}
	if buildEnabled {
		if !validBuilderImageDigest(workspaceProvisionerImageReference) {
			return "", func() {}, fmt.Errorf("product config: build capability requires a bundled digest-pinned workspace provisioner image reference; got %q", workspaceProvisionerImageReference)
		}
		// Builder images are operator-supplied (not packaged). When a digest is
		// provided (day-2 default), it must be digest-pinned; otherwise omit.
		if builderImageReference != "" && !validBuilderImageDigest(builderImageReference) {
			return "", func() {}, fmt.Errorf("product config: builderImageDigest must be digest-pinned when set; got %q", builderImageReference)
		}
	}
	if artifactEnabled && len(registry) > 0 && !validArtifactServerImageDigest(artifactServerImageReference) {
		return "", func() {}, fmt.Errorf("product config: artifact capability requires bundled registry.local/artifact-server@sha256 image reference; got %q", artifactServerImageReference)
	}
	if !validBlobStorageImageDigest(blobStorageImageReference) {
		return "", func() {}, fmt.Errorf("product config: foundation requires a bundled registry.local/blob-storage@sha256 image reference; got %q", blobStorageImageReference)
	}
	if hostAgentEnabled && !validHostAgentImageDigest(hostAgentImageReference) {
		return "", func() {}, fmt.Errorf("product config: host capability requires a bundled digest-pinned appliance host agent image reference; got %q", hostAgentImageReference)
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
	config["applianceCatalog"] = catalog.Document
	config["applianceName"] = identity.Name
	config["dnsZoneName"] = identity.Zone
	// host mDNS / Wi-Fi AP enablement is day-2 only (control-plane / host-agent
	// APIs after admin login). Install stages offline host packages; services
	// stay off until an operator enables them via the UI/API.
	delete(config, "hostMDNSEnabled")
	delete(config, "hostWifiAPEnabled")
	config["canonicalOrigin"] = "https://" + identity.FQDN
	if ip := strings.TrimSpace(nodeIPv4); ip != "" {
		config["nodeIPv4"] = ip
	} else {
		delete(config, "nodeIPv4")
	}
	if artifactEnabled {
		config["artifactServerBaseURL"] = DefaultArtifactServerBaseURL
	} else {
		delete(config, "artifactServerBaseURL")
	}
	if dnsEnabled {
		config["dnsReadyURL"] = DefaultDNSReadyURL
		config["dnsConfigMapNamespace"] = "dns"
		config["dnsConfigMapName"] = "dns-server-config"
		// Do not seed product A records at install. Operators add the
		// appliance FQDN on the landns appliance via API/UI (or peer publish).
		config["dnsBootstrapHostname"] = ""
		config["dnsBootstrapIPv4"] = ""
		config["dnsAllowFakeZoneSync"] = false
	} else {
		delete(config, "dnsReadyURL")
		delete(config, "dnsConfigMapNamespace")
		delete(config, "dnsConfigMapName")
		delete(config, "dnsBootstrapHostname")
		delete(config, "dnsBootstrapIPv4")
		delete(config, "dnsAllowFakeZoneSync")
	}
	if inferenceEnabled {
		config["inferenceGatewayBaseURL"] = DefaultInferenceGatewayBaseURL
	} else {
		delete(config, "inferenceGatewayBaseURL")
	}
	if workspaceProvisionerImageReference != "" {
		config["workspaceProvisionerImageDigest"] = workspaceProvisionerImageReference
	} else {
		delete(config, "workspaceProvisionerImageDigest")
	}
	if builderImageReference != "" {
		config["builderImageDigest"] = builderImageReference
	} else {
		delete(config, "builderImageDigest")
	}
	if registryConfig := ServiceRegistryConfig(resolvedModules); registryConfig != nil {
		config["serviceRegistry"] = registryConfig
	} else {
		delete(config, "serviceRegistry")
	}
	delete(config, "allowedBuilderImageDigests")
	// Runtime build catalogs are uploaded post-install via PUT /api/v1/builder/catalog.
	config["buildCatalog"] = map[string]any{}
	delete(config, "allowedGitSourceHosts")
	values["config"] = config
	blobStorage, _ := values["blobStorage"].(map[string]any)
	if blobStorage == nil {
		blobStorage = map[string]any{}
	}
	image, _ := blobStorage["image"].(map[string]any)
	if image == nil {
		image = map[string]any{}
	}
	image["repository"] = "registry.local/blob-storage"
	image["digest"] = strings.TrimPrefix(blobStorageImageReference, "registry.local/blob-storage@")
	image["pullPolicy"] = "IfNotPresent"
	blobStorage["image"] = image
	values["blobStorage"] = blobStorage

	// controlplane lives in the Helm release namespace (zonctl defaultChartNamespace =
	// ace-system). Co-packaged apps go in ace-apps.
	values["namespace"] = map[string]any{"create": false}
	values["appsNamespace"] = map[string]any{
		"create": false,
		"name":   ControlPlaneAppsNamespace,
	}
	// Default empty: lab install injects appliance-image-pull via
	// InjectImagePullSecrets when --image-pull-registry is set.
	if _, has := values["imagePullSecrets"]; !has {
		values["imagePullSecrets"] = []any{}
	}
	values["applicationNamespace"] = map[string]any{
		"create": true,
		"name":   ApplicationNamespace,
	}

	networkPolicy, _ := values["networkPolicy"].(map[string]any)
	if networkPolicy == nil {
		networkPolicy = map[string]any{}
	}
	if artifactEnabled {
		// The artifact server ships in the dedicated artifacts namespace; CP
		// egress must target that namespace, not the control-plane namespace.
		networkPolicy["registryNamespaceLabel"] = map[string]any{
			"kubernetes.io/metadata.name": "artifacts",
		}
		networkPolicy["registryPodLabels"] = map[string]any{
			"app.kubernetes.io/name": "appliance-registry",
		}
		networkPolicy["registryPort"] = 5000
	}
	if dnsEnabled {
		// CoreDNS readiness (:8181) is polled by the control plane; allow
		// that egress only when the dns capability is enabled.
		networkPolicy["dnsNamespaceLabel"] = map[string]any{
			"kubernetes.io/metadata.name": "dns",
		}
		networkPolicy["dnsPodLabels"] = map[string]any{
			"app.kubernetes.io/name": "dns-server",
		}
		networkPolicy["dnsReadyPort"] = 8181
	} else {
		delete(networkPolicy, "dnsNamespaceLabel")
		delete(networkPolicy, "dnsPodLabels")
		delete(networkPolicy, "dnsReadyPort")
	}
	if inferenceEnabled {
		networkPolicy["inferenceNamespaceLabel"] = map[string]any{
			"kubernetes.io/metadata.name": "inference",
		}
		networkPolicy["inferencePodLabels"] = map[string]any{
			"app.kubernetes.io/name": "inference-gateway",
		}
		networkPolicy["inferencePort"] = 8080
	} else {
		delete(networkPolicy, "inferenceNamespaceLabel")
		delete(networkPolicy, "inferencePodLabels")
		delete(networkPolicy, "inferencePort")
	}
	if artifactEnabled || dnsEnabled || inferenceEnabled {
		values["networkPolicy"] = networkPolicy
	}

	hostAgent, _ := values["hostAgent"].(map[string]any)
	if hostAgent == nil {
		hostAgent = map[string]any{}
	}
	hostAgent["enabled"] = hostAgentEnabled
	imageConfig, _ := hostAgent["image"].(map[string]any)
	if imageConfig == nil {
		imageConfig = map[string]any{}
	}
	if hostAgentEnabled {
		imageConfig["reference"] = hostAgentImageReference
	} else {
		delete(imageConfig, "reference")
	}
	hostAgent["image"] = imageConfig
	values["hostAgent"] = hostAgent

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

// InjectImagePullSecrets rewrites a prepared values file so Helm deployments
// reference the installer-managed dockerconfig secret. No-op when secretName
// is empty.
func InjectImagePullSecrets(valuesPath, secretName string) error {
	secretName = strings.TrimSpace(secretName)
	if secretName == "" {
		return nil
	}
	data, err := os.ReadFile(valuesPath)
	if err != nil {
		return fmt.Errorf("product config: read values for image-pull secrets: %w", err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("product config: parse values for image-pull secrets: %w", err)
	}
	if values == nil {
		values = map[string]any{}
	}
	values["imagePullSecrets"] = []any{
		map[string]any{"name": secretName},
	}
	rendered, err := yaml.Marshal(values)
	if err != nil {
		return fmt.Errorf("product config: render image-pull secrets values: %w", err)
	}
	if err := os.WriteFile(valuesPath, rendered, 0o600); err != nil {
		return fmt.Errorf("product config: write image-pull secrets values: %w", err)
	}
	return nil
}

// PrepareRegistryValuesFile renders the small installer-owned values layer
// for the separate artifact server release. The chart archive remains
// immutable; only the verified digest pins, public-key Secret name, and
// persistence policy are supplied at install time.
func PrepareRegistryValuesFile(baseDir, artifactServerImageReference, fqdn string) (string, func(), error) {
	if !validArtifactServerImageDigest(artifactServerImageReference) {
		return "", func() {}, fmt.Errorf("product config: invalid artifact server image reference %q", artifactServerImageReference)
	}
	host := strings.TrimSpace(fqdn)
	if host == "" {
		return "", func() {}, fmt.Errorf("product config: registry token realm requires appliance FQDN")
	}
	values := map[string]any{
		"namespace": map[string]any{"create": false, "name": "artifacts"},
		"image": map[string]any{
			"repository": "registry.local/artifact-server",
			"digest":     strings.TrimPrefix(strings.TrimSpace(artifactServerImageReference), "registry.local/artifact-server@"),
			"pullPolicy": "IfNotPresent",
		},
		"auth": map[string]any{
			"realm":               "https://" + host + "/api/v1/registry/token",
			"service":             "artifact-server",
			"publicKeySecretName": DefaultRegistryPublicKeySecret,
			"publicKeySecretKey":  "registry_ed25519_public.pem",
		},
		// Keep the public /v2 route host-agnostic by default so it remains
		// reachable through the same appliance IP/URL operators already use
		// for the UI and API, even when the token realm prefers the
		// appliance FQDN as canonical origin.
		"ingress": map[string]any{},
		"persistence": map[string]any{
			"storageClassName": "local-path", "accessMode": "ReadWriteOnce", "size": "100Gi",
		},
		"networkPolicy": map[string]any{
			"enabled": true,
			"controlPlaneNamespaceLabel": map[string]any{
				"kubernetes.io/metadata.name": "ace-system",
			},
			"controlPlanePodLabels": map[string]any{
				// Matches appliance-control-plane chart selectorLabels
				// (controlplane Deployment), not the chart/image name.
				"app.kubernetes.io/name": "controlplane",
			},
			// K3s ships Traefik in kube-system; empty selectors leave /v2 unreachable.
			"traefikNamespaceLabel": map[string]any{
				"kubernetes.io/metadata.name": "kube-system",
			},
		},
		"logs": map[string]any{
			"hostPath": "/data/zon/logs/artifactserver",
			"prepare":  map[string]any{"enabled": false},
		},
	}
	rendered, err := yaml.Marshal(values)
	if err != nil {
		return "", func() {}, fmt.Errorf("product config: render registry values: %w", err)
	}
	tmp, err := os.CreateTemp(baseDir, ".zonctl-registry-values-*.yaml")
	if err != nil {
		return "", func() {}, fmt.Errorf("product config: create registry values file: %w", err)
	}
	cleanup := func() { _ = os.Remove(tmp.Name()) }
	if _, err := tmp.Write(rendered); err != nil {
		tmp.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("product config: write registry values file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("product config: close registry values file: %w", err)
	}
	return tmp.Name(), cleanup, nil
}

// PrepareDNSValuesFile renders the small installer-owned values layer for
// the separate appliance-dns (CoreDNS) release. The chart archive stays
// immutable; install supplies the digest pin, upstream resolvers, zone
// name, and NS glue IPv4 only. Product host A records are not seeded here
// — they are created later through the control-plane DNS records API/UI
// (or peer publish). nsIPv4 is only glue for ns.<zone>; upstreams are the
// resolvers CoreDNS forwards everything else to.
func PrepareDNSValuesFile(baseDir, corednsImageReference, dnsZone, nsIPv4 string, upstreams ...string) (string, func(), error) {
	if !validDNSImageDigest(corednsImageReference) {
		return "", func() {}, fmt.Errorf("product config: invalid coredns image reference %q", corednsImageReference)
	}
	zone, err := NormalizeDNSZone(dnsZone)
	if err != nil {
		return "", func() {}, err
	}
	resolvers := make([]string, 0, len(upstreams))
	for _, resolver := range upstreams {
		resolver = strings.TrimSpace(resolver)
		if resolver != "" {
			resolvers = append(resolvers, resolver)
		}
	}
	if len(resolvers) == 0 {
		resolvers = []string{"1.1.1.1", "8.8.8.8"}
	}
	nsIPv4 = strings.TrimSpace(nsIPv4)
	if nsIPv4 == "" {
		return "", func() {}, fmt.Errorf("product config: dns local zone ns ipv4 must not be empty")
	}
	values := map[string]any{
		// create=false: zonctl EnsureNamespace already creates the dns
		// namespace (with privileged PSA labels) before Helm runs. If the
		// chart also owned Namespace, Helm would refuse to adopt the
		// pre-created object (missing meta.helm.sh ownership).
		"namespace": map[string]any{"create": false, "name": "dns"},
		"image": map[string]any{
			"repository": "registry.local/coredns",
			"digest":     strings.TrimPrefix(strings.TrimSpace(corednsImageReference), "registry.local/coredns@"),
			"pullPolicy": "IfNotPresent",
		},
		// LAN DNS must be reachable at the standard port 53 from every
		// device on the network, not just from inside the cluster's pod
		// network, so it runs with the host's own network namespace
		// instead of a ClusterIP Service.
		"hostNetwork": true,
		"localZone": map[string]any{
			"name":     zone,
			"hostname": "",
			"ipv4":     nsIPv4,
		},
		"upstreamResolvers": resolvers,
		"logs": map[string]any{
			"hostPath": "/data/zon/logs/dns",
			"prepare":  map[string]any{"enabled": false},
		},
	}
	rendered, err := yaml.Marshal(values)
	if err != nil {
		return "", func() {}, fmt.Errorf("product config: render dns values: %w", err)
	}
	tmp, err := os.CreateTemp(baseDir, ".zonctl-dns-values-*.yaml")
	if err != nil {
		return "", func() {}, fmt.Errorf("product config: create dns values file: %w", err)
	}
	cleanup := func() { _ = os.Remove(tmp.Name()) }
	if _, err := tmp.Write(rendered); err != nil {
		tmp.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("product config: write dns values file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("product config: close dns values file: %w", err)
	}
	return tmp.Name(), cleanup, nil
}

func PrepareInferenceValuesFile(baseDir, inferenceRuntimeImageReference string) (string, func(), error) {
	if !validInferenceRuntimeImageDigest(inferenceRuntimeImageReference) {
		return "", func() {}, fmt.Errorf("product config: invalid inference-runtime image reference %q", inferenceRuntimeImageReference)
	}
	values := map[string]any{
		"namespace": map[string]any{"create": false, "name": "inference"},
		"image": map[string]any{
			"repository": "registry.local/inference-runtime",
			"digest":     strings.TrimPrefix(strings.TrimSpace(inferenceRuntimeImageReference), "registry.local/inference-runtime@"),
			"pullPolicy": "IfNotPresent",
		},
	}
	rendered, err := yaml.Marshal(values)
	if err != nil {
		return "", func() {}, fmt.Errorf("product config: render inference values: %w", err)
	}
	tmp, err := os.CreateTemp(baseDir, ".zonctl-inference-values-*.yaml")
	if err != nil {
		return "", func() {}, fmt.Errorf("product config: create inference values file: %w", err)
	}
	cleanup := func() { _ = os.Remove(tmp.Name()) }
	if _, err := tmp.Write(rendered); err != nil {
		tmp.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("product config: write inference values file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("product config: close inference values file: %w", err)
	}
	return tmp.Name(), cleanup, nil
}

func validBuilderImageDigest(image string) bool {
	image = strings.TrimSpace(image)
	if !sha256ImageDigestRE.MatchString(image) {
		return false
	}
	_, digest, _ := strings.Cut(image, "@sha256:")
	return digest != placeholderImageDigestHex
}

func validArtifactServerImageDigest(image string) bool {
	image = strings.TrimSpace(image)
	if !strings.HasPrefix(image, "registry.local/artifact-server@sha256:") || !sha256ImageDigestRE.MatchString(image) {
		return false
	}
	_, digest, _ := strings.Cut(image, "@sha256:")
	return digest != placeholderImageDigestHex
}

func validBlobStorageImageDigest(image string) bool {
	image = strings.TrimSpace(image)
	if !strings.HasPrefix(image, "registry.local/blob-storage@sha256:") || !sha256ImageDigestRE.MatchString(image) {
		return false
	}
	return strings.TrimPrefix(image, "registry.local/blob-storage@sha256:") != placeholderImageDigestHex
}

func validDNSImageDigest(image string) bool {
	image = strings.TrimSpace(image)
	if !strings.HasPrefix(image, "registry.local/coredns@sha256:") || !sha256ImageDigestRE.MatchString(image) {
		return false
	}
	_, digest, _ := strings.Cut(image, "@sha256:")
	return digest != placeholderImageDigestHex
}

func validInferenceRuntimeImageDigest(image string) bool {
	image = strings.TrimSpace(image)
	if !strings.HasPrefix(image, "registry.local/inference-runtime@sha256:") || !sha256ImageDigestRE.MatchString(image) {
		return false
	}
	_, digest, _ := strings.Cut(image, "@sha256:")
	return digest != placeholderImageDigestHex
}

func validHostAgentImageDigest(image string) bool {
	image = strings.TrimSpace(image)
	if !strings.HasPrefix(image, "registry.local/appliance-host-agent@sha256:") || !sha256ImageDigestRE.MatchString(image) {
		return false
	}
	_, digest, _ := strings.Cut(image, "@sha256:")
	return digest != placeholderImageDigestHex
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
