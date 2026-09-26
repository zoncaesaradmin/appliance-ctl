package productconfig

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/zoncaesaradmin/appliance-ctl/internal/metadatabundle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/runtimeconfig"
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
	InfrastructureNamespace   = "ace-infra"
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
// pods. controlPlaneNS is the chart release namespace for controlplane, the
// controlplane. Shared message broker and blob storage live in ace-infra.
// kube-system
// and other K3s system namespaces are intentionally excluded.
func ProductNamespaces(controlPlaneNS string) []string {
	controlPlaneNS = strings.TrimSpace(controlPlaneNS)
	if controlPlaneNS == "" {
		controlPlaneNS = "ace-system"
	}
	return []string{
		InfrastructureNamespace,
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
	CapabilityBase          Capability = "base"
	CapabilityLANDiscovery  Capability = "lan-discovery"
	CapabilityHost          Capability = "host"
	CapabilityWorkflows     Capability = "workflows"
	CapabilityBuild         Capability = "build"
	CapabilityFiles         Capability = "files"
	CapabilityArtifact      Capability = "artifact"
	CapabilityDNS           Capability = "dns"
	CapabilityInference     Capability = "inference"
	CapabilityOpenWebUI     Capability = "open-webui"
	CapabilityVideo         Capability = "video"
	CapabilityApplications  Capability = "applications"
	CapabilityPlaintextHTTP Capability = "plaintext-http"
)

type ProfileDefinition struct {
	Capabilities []Capability
}

type ProfileCatalog map[string]ProfileDefinition

// ProfileCatalogFromMetadata converts the signed metadata-bundle policy into
// the typed installer representation. Profile policy never lives in zonctl.
func ProfileCatalogFromMetadata(definitions map[string]metadatabundle.ProfileDefinition) (ProfileCatalog, error) {
	if len(definitions) == 0 {
		return nil, fmt.Errorf("profile catalog is empty")
	}
	catalog := make(ProfileCatalog, len(definitions))
	for name, definition := range definitions {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("profile catalog contains an empty profile name")
		}
		capabilities := make([]Capability, len(definition.Capabilities))
		for i, capability := range definition.Capabilities {
			capabilities[i] = Capability(strings.TrimSpace(capability))
		}
		catalog[name] = ProfileDefinition{Capabilities: capabilities}
	}
	return catalog, nil
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
	// control plane authenticates and reverse-proxies /ai/v1/* here.
	DefaultInferenceGatewayBaseURL = "http://inference-gateway.inference.svc.cluster.local:8080"
	// DefaultLANDNSZone is the CoreDNS local-zone suffix for LAN A records.
	// Must not be ".local" — systemd-resolved (and dig) treat .local as
	// Multicast DNS and will never send those queries to unicast DNS.
	DefaultLANDNSZone = "appliance.internal"
)

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

// SelectApplianceProfile chooses the requested or current profile name without
// interpreting policy. The signed metadata bundle is the only authority that
// validates the name and resolves capabilities.
func SelectApplianceProfile(requested, current string) string {
	profile := strings.TrimSpace(requested)
	if profile == "" {
		profile = strings.TrimSpace(current)
	}
	if profile == "" {
		profile = ProfileCore
	}
	return profile
}

func ResolveApplianceProfileWithCatalog(requested, current string, catalog ProfileCatalog) (string, error) {
	profile := SelectApplianceProfile(requested, current)
	if _, ok := catalog[profile]; !ok {
		supported := make([]string, 0, len(catalog))
		for name := range catalog {
			supported = append(supported, name)
		}
		sort.Strings(supported)
		return "", fmt.Errorf("unknown appliance profile %q (supported: %s)", profile, strings.Join(supported, ", "))
	}
	return profile, nil
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

func PrepareValuesFile(baseValuesPath, profile string, profileCatalog ProfileCatalog, workspaceProvisionerImageReference, builderImageReference, hostAgentImageReference, applianceName, dnsZone, nodeIPv4 string, registry ...string) (string, func(), error) {
	return prepareValuesFile(baseValuesPath, profile, profileCatalog, workspaceProvisionerImageReference, builderImageReference, hostAgentImageReference, applianceName, dnsZone, nodeIPv4, nil, false, registry...)
}

func PrepareValuesFileForRuntime(baseValuesPath, profile string, profileCatalog ProfileCatalog, workspaceProvisionerImageReference, builderImageReference, hostAgentImageReference, applianceName, dnsZone, nodeIPv4 string, runtime runtimeconfig.Selection, webUIEnabled bool, registry ...string) (string, func(), error) {
	return prepareValuesFile(baseValuesPath, profile, profileCatalog, workspaceProvisionerImageReference, builderImageReference, hostAgentImageReference, applianceName, dnsZone, nodeIPv4, &runtime, webUIEnabled, registry...)
}

func prepareValuesFile(baseValuesPath, profile string, profileCatalog ProfileCatalog, workspaceProvisionerImageReference, builderImageReference, hostAgentImageReference, applianceName, dnsZone, nodeIPv4 string, runtime *runtimeconfig.Selection, webUIEnabled bool, registry ...string) (string, func(), error) {
	effectiveProfile, err := ResolveApplianceProfileWithCatalog(profile, "", profileCatalog)
	if err != nil {
		return "", func() {}, err
	}
	resolvedModules := ResolveModulesWithCatalog(effectiveProfile, profileCatalog, AlwaysEntitled{}, BuiltInModuleCatalog())
	hostAgentEnabled := HostAgentEnabled(resolvedModules) || HasCapabilityInCatalog(effectiveProfile, CapabilityApplications, profileCatalog)
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
		return "", func() {}, fmt.Errorf("product config: host or application capability requires a bundled digest-pinned appliance host agent image reference; got %q", hostAgentImageReference)
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
	// Helm needs capability facts for install-time RBAC and token mounts, but
	// profile policy remains exclusively in the signed metadata catalog. Pass
	// the resolved set rather than duplicating individual feature booleans.
	capabilities := capabilitiesForProfileInCatalog(effectiveProfile, profileCatalog)
	enabledCapabilities := make([]string, len(capabilities))
	for i, capability := range capabilities {
		enabledCapabilities[i] = string(capability)
	}
	config["enabledCapabilities"] = enabledCapabilities
	delete(config, "applianceCatalog")
	config["applianceName"] = identity.Name
	config["dnsZoneName"] = identity.Zone
	// mDNS is enabled by the installer for every appliance;
	// Wi-Fi AP stays explicitly day-2. Neither value is a chart-side policy.
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
		if runtime != nil {
			if err := runtimeconfig.ValidateInference(*runtime); err != nil {
				return "", func() {}, fmt.Errorf("product config: %w", err)
			}
			config["inferenceRuntimePackage"] = runtime.Package
			config["inferenceEngine"] = runtime.InferenceEngine
			config["inferenceArchitecture"] = runtime.Architecture
		}
	} else {
		delete(config, "inferenceGatewayBaseURL")
		delete(config, "inferenceRuntimePackage")
		delete(config, "inferenceEngine")
		delete(config, "inferenceArchitecture")
	}
	config["webUIEnabled"] = inferenceEnabled && webUIEnabled && HasCapabilityInCatalog(effectiveProfile, CapabilityOpenWebUI, profileCatalog)
	ingress, _ := values["ingress"].(map[string]any)
	if ingress == nil {
		ingress = map[string]any{}
	}
	ingress["webUIEnabled"] = inferenceEnabled && webUIEnabled && HasCapabilityInCatalog(effectiveProfile, CapabilityOpenWebUI, profileCatalog)
	values["ingress"] = ingress
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
	// Shared foundation service, brought up before the control plane.
	blobStorage["endpoint"] = "http://blob-storage.ace-infra.svc.cluster.local:9000"
	delete(blobStorage, "namespace")
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

func hostNVIDIARuntimeAvailable() bool {
	// Usable host GPU = NVIDIA character device present (driver loaded) plus
	// nvidia-ctk on PATH so install can configure K3s containerd afterward.
	// Do NOT require K3s containerd config.toml to already mention "nvidia":
	// that stanza is an install outcome, not a host prerequisite.
	// nvidia-container-runtime alone is insufficient: EnsureK3sRuntime always
	// invokes nvidia-ctk runtime configure.
	if _, err := os.Stat("/dev/nvidiactl"); err != nil {
		return false
	}
	if _, err := exec.LookPath("nvidia-ctk"); err != nil {
		return false
	}
	return true
}

// hostNVIDIACheck is overridable in unit tests.
var hostNVIDIACheck = hostNVIDIARuntimeAvailable

// HostNVIDIAAvailable reports whether the install host has a usable NVIDIA
// GPU and container toolkit for inference acceleration.
func HostNVIDIAAvailable() bool {
	return hostNVIDIACheck()
}

// OverrideHostNVIDIACheckForTest replaces the NVIDIA probe for unit tests.
// Call the returned function to restore the previous probe.
func OverrideHostNVIDIACheckForTest(fn func() bool) func() {
	prev := hostNVIDIACheck
	if fn == nil {
		hostNVIDIACheck = hostNVIDIARuntimeAvailable
	} else {
		hostNVIDIACheck = fn
	}
	return func() { hostNVIDIACheck = prev }
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

func PrepareInferenceValuesFile(baseDir, inferenceRuntimeImageReference, inferenceManagerImageReference, openWebUIImageReference, openWebUIGatewayImageReference string, runtime runtimeconfig.Selection) (string, func(), error) {
	if err := runtimeconfig.ValidateInference(runtime); err != nil {
		return "", func() {}, err
	}
	if !validInferenceRuntimeImageDigest(inferenceRuntimeImageReference) {
		return "", func() {}, fmt.Errorf("product config: invalid inference-runtime image reference %q", inferenceRuntimeImageReference)
	}
	if !validInferenceManagerImageDigest(inferenceManagerImageReference) {
		return "", func() {}, fmt.Errorf("product config: invalid inference-manager image reference %q", inferenceManagerImageReference)
	}
	if (strings.TrimSpace(openWebUIImageReference) == "") != (strings.TrimSpace(openWebUIGatewayImageReference) == "") {
		return "", func() {}, fmt.Errorf("product config: Open WebUI and its gateway image references must be supplied together")
	}
	if openWebUIImageReference != "" && !validOpenWebUIImageDigest(openWebUIImageReference) {
		return "", func() {}, fmt.Errorf("product config: invalid Open WebUI image reference %q", openWebUIImageReference)
	}
	if openWebUIGatewayImageReference != "" && !validOpenWebUIGatewayImageDigest(openWebUIGatewayImageReference) {
		return "", func() {}, fmt.Errorf("product config: invalid Open WebUI gateway image reference %q", openWebUIGatewayImageReference)
	}
	gpuAvailable := hostNVIDIACheck()
	if runtimeconfig.RequiresGPU(runtime) && !gpuAvailable {
		return "", func() {}, fmt.Errorf("product config: accelerated inference package %q requires a usable GPU on the install host", runtime.Package)
	}
	// Standard (Ollama) may use a host GPU when present; accelerated always does.
	gpuEnabled := gpuAvailable
	values := map[string]any{
		"namespace": map[string]any{"create": false, "name": "inference"},
		"runtime": map[string]any{
			"engine": runtime.InferenceEngine,
		},
		"image": map[string]any{
			"repository": "registry.local/inference-runtime",
			"digest":     strings.TrimPrefix(strings.TrimSpace(inferenceRuntimeImageReference), "registry.local/inference-runtime@"),
			"pullPolicy": "IfNotPresent",
		},
		"managerImage": map[string]any{
			"repository": "registry.local/inference-manager",
			"digest":     strings.TrimPrefix(strings.TrimSpace(inferenceManagerImageReference), "registry.local/inference-manager@"),
			"pullPolicy": "IfNotPresent",
		},
		"openWebUI": map[string]any{
			"enabled": strings.TrimSpace(openWebUIImageReference) != "",
			"image": map[string]any{
				"repository": "registry.local/open-webui",
				"digest":     strings.TrimPrefix(strings.TrimSpace(openWebUIImageReference), "registry.local/open-webui@"),
				"pullPolicy": "IfNotPresent",
			},
			"gatewayImage": map[string]any{
				"repository": "registry.local/open-webui-gateway",
				"digest":     strings.TrimPrefix(strings.TrimSpace(openWebUIGatewayImageReference), "registry.local/open-webui-gateway@"),
				"pullPolicy": "IfNotPresent",
			},
		},
		"gpu": map[string]any{
			"enabled":            gpuEnabled,
			"runtimeClassName":   "nvidia",
			"visibleDevices":     "all",
			"driverCapabilities": "all",
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

func validInferenceManagerImageDigest(image string) bool {
	image = strings.TrimSpace(image)
	if !strings.HasPrefix(image, "registry.local/inference-manager@sha256:") || !sha256ImageDigestRE.MatchString(image) {
		return false
	}
	_, digest, _ := strings.Cut(image, "@sha256:")
	return digest != placeholderImageDigestHex
}

func validOpenWebUIImageDigest(image string) bool {
	return validRegistryLocalImageDigest(image, "open-webui")
}

func validOpenWebUIGatewayImageDigest(image string) bool {
	return validRegistryLocalImageDigest(image, "open-webui-gateway")
}

func validRegistryLocalImageDigest(image, name string) bool {
	image = strings.TrimSpace(image)
	prefix := "registry.local/" + name + "@sha256:"
	if !strings.HasPrefix(image, prefix) || !sha256ImageDigestRE.MatchString(image) {
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
