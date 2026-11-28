package productconfig

import (
	"crypto/sha256"
	"fmt"
	"net/url"
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
	ProfileCore          = "core"
	ProfileStorage       = "storage"
	ProfileLANDNS        = "landns"
	ProfileStorageLANDNS = "storage-landns"
	ProfileLANLLM        = "lanllm"
	ProfileTraining      = "training"
	ProfileGeoZone       = "geo-zone"

	// ControlPlaneAppsNamespace hosts ui-server, host-agent, and
	// action-runtime. controlplane itself uses defaultChartNamespace
	// (ace-system).
	ControlPlaneAppsNamespace = "ace-apps"
	// ApplicationCoreNamespace hosts shared application prerequisites such as
	// the future platform authentication service. It is deliberately separate
	// from ace-apps so those prerequisites can be enabled or moved as a unit.
	ApplicationCoreNamespace = "ace-app-core"
	InfrastructureNamespace  = "ace-infra"
	// Fixed product namespaces for capability-scoped charts (in addition to
	// the control-plane release namespace and ControlPlaneAppsNamespace).
	ArtifactsNamespace = "artifacts"
	DNSNamespace       = "dns"
	InferenceNamespace = "inference"

	// ImagePullSecretName mirrors helm.ImagePullSecretName for chart values
	// injection. Secrets are namespaced; when lab image-pull is configured,
	// zonctl places this secret in every product namespace (not kube-system).
	ImagePullSecretName = "appliance-image-pull"
)

// ProductNamespaces returns every appliance-owned namespace that may run product
// pods. controlPlaneNS is the chart release namespace for controlplane.
// Shared message broker and blob storage live in ace-infra.
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
		ApplicationCoreNamespace,
		ControlPlaneAppsNamespace,
		ArtifactsNamespace,
		DNSNamespace,
		InferenceNamespace,
	}
}

// Capability is the granular unit appliance behavior should actually be
// gated on, not the profile name itself. A profile is just a named bundle
// of capabilities; more than one profile can enable the same capability,
// so code that cares whether a capability is present should check the
// capability, not compare against a specific profile
// string. This mirrors the canonical mapping in appliance-code
// (services/controlplane/internal/appliance/appliance.go's Capability
// type and profileCatalog) — kept in sync by hand, the same way
// ApplianceSharedFSGID in the hostdirs package is.
type Capability string

const (
	CapabilityBase                Capability = "base"
	CapabilityActions             Capability = "actions"
	CapabilityChannelIntegrations Capability = "channel-integrations"
	CapabilityCommerce            Capability = "commerce"
	CapabilityApplicationAuth     Capability = "application-auth"
	CapabilityApplicationIdentity Capability = "application-identity"
	CapabilityLANDiscovery        Capability = "lan-discovery"
	CapabilityHost                Capability = "host"
	CapabilityFiles               Capability = "files"
	CapabilityArtifact            Capability = "artifact"
	CapabilityDNS                 Capability = "dns"
	CapabilityInference           Capability = "inference"
	CapabilityOpenWebUI           Capability = "open-webui"
	CapabilityVideo               Capability = "video"
	CapabilityGuestAccess         Capability = "guest-access"
	CapabilityFocusContent        Capability = "focus-content"
	CapabilityPlaintextHTTP       Capability = "plaintext-http"
	CapabilityGeoSpatialStore     Capability = "geo-spatial-store"
	CapabilityGeoDataAPI          Capability = "geo-data-api"
	CapabilityGeoBasemap          Capability = "geo-basemap"
	CapabilityGeoZoneEditor       Capability = "geo-zone-editor"
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
	// DefaultInferenceRoutingRegistry is cluster-scoped desired routing state.
	// It is used even on a single-node cluster so the first worker expansion
	// does not migrate a local singleton into a new control plane.
	DefaultInferenceRoutingRegistry = "appliance-inference-routing"
	// DefaultOpenWebUIHealthURL is the session bridge health endpoint. The
	// control plane checks it before minting a one-time browser launch grant.
	DefaultOpenWebUIHealthURL = "http://inference-gateway-open-webui-gateway.inference.svc.cluster.local:8081/healthz"
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

func normalizePublicOriginAndTLS(publicOrigin, tlsTermination, internalFQDN string) (string, string, string, error) {
	tlsTermination = strings.ToLower(strings.TrimSpace(tlsTermination))
	if tlsTermination == "" {
		tlsTermination = "traefik"
	}
	if tlsTermination != "traefik" && tlsTermination != "cloudflare" {
		return "", "", "", fmt.Errorf("product config: tls termination must be traefik or cloudflare, got %q", tlsTermination)
	}
	publicOrigin = strings.TrimRight(strings.TrimSpace(publicOrigin), "/")
	if publicOrigin == "" {
		publicOrigin = "https://" + internalFQDN
	}
	u, err := url.Parse(publicOrigin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
		return "", "", "", fmt.Errorf("product config: public origin must be an absolute HTTPS URL without a port or path, got %q", publicOrigin)
	}
	return publicOrigin, u.Hostname(), tlsTermination, nil
}

func PrepareValuesFile(baseValuesPath, profile string, profileCatalog ProfileCatalog, hostAgentImageReference, applianceName, dnsZone, nodeIPv4 string, registry ...string) (string, func(), error) {
	return prepareValuesFile(baseValuesPath, profile, profileCatalog, hostAgentImageReference, applianceName, dnsZone, nodeIPv4, nil, false, "", "", "", "", registry...)
}

func PrepareValuesFileForRuntime(baseValuesPath, profile string, profileCatalog ProfileCatalog, hostAgentImageReference, applianceName, dnsZone, nodeIPv4 string, runtime runtimeconfig.Selection, webUIEnabled bool, registry ...string) (string, func(), error) {
	return PrepareValuesFileForRuntimeWithPublicOrigin(baseValuesPath, profile, profileCatalog, hostAgentImageReference, applianceName, dnsZone, nodeIPv4, runtime, webUIEnabled, "", "", registry...)
}

// PrepareValuesFileForRuntimeWithPublicOrigin renders the installer-owned
// values layer while keeping the appliance's internal identity separate from
// the externally visible application origin. publicOrigin is an absolute
// https URL without a path. tlsTermination is "traefik" (the default) or
// "cloudflare"; the latter exposes the public routes on Traefik's plaintext
// web entrypoint because Cloudflare terminates public HTTPS.
func PrepareValuesFileForRuntimeWithPublicOrigin(baseValuesPath, profile string, profileCatalog ProfileCatalog, hostAgentImageReference, applianceName, dnsZone, nodeIPv4 string, runtime runtimeconfig.Selection, webUIEnabled bool, publicOrigin, tlsTermination string, registry ...string) (string, func(), error) {
	return PrepareValuesFileForRuntimeWithPublicOrigins(baseValuesPath, profile, profileCatalog, hostAgentImageReference, applianceName, dnsZone, nodeIPv4, runtime, webUIEnabled, publicOrigin, "", tlsTermination, registry...)
}

// PrepareValuesFileForRuntimeWithPublicOrigins renders the installer-owned
// values layer with independent browser and channel-integration origins.
// channelIntegrationOrigin is an absolute HTTPS URL without a path. When it
// is empty, the application public origin is used for backwards compatibility.
func PrepareValuesFileForRuntimeWithPublicOrigins(baseValuesPath, profile string, profileCatalog ProfileCatalog, hostAgentImageReference, applianceName, dnsZone, nodeIPv4 string, runtime runtimeconfig.Selection, webUIEnabled bool, publicOrigin, channelIntegrationOrigin, tlsTermination string, registry ...string) (string, func(), error) {
	return PrepareValuesFileForRuntimeWithPublicOriginsAndAuthDeliveryMode(baseValuesPath, profile, profileCatalog, hostAgentImageReference, applianceName, dnsZone, nodeIPv4, runtime, webUIEnabled, publicOrigin, channelIntegrationOrigin, tlsTermination, "", registry...)
}

// PrepareValuesFileForRuntimeWithPublicOriginsAndAuthDeliveryMode renders the
// installer-owned values layer and selects the Auth Service OTP delivery
// transport. Empty authServiceOTPDeliveryMode keeps the production default,
// event; local is intended only for development/test installs.
func PrepareValuesFileForRuntimeWithPublicOriginsAndAuthDeliveryMode(baseValuesPath, profile string, profileCatalog ProfileCatalog, hostAgentImageReference, applianceName, dnsZone, nodeIPv4 string, runtime runtimeconfig.Selection, webUIEnabled bool, publicOrigin, channelIntegrationOrigin, tlsTermination, authServiceOTPDeliveryMode string, registry ...string) (string, func(), error) {
	return prepareValuesFile(baseValuesPath, profile, profileCatalog, hostAgentImageReference, applianceName, dnsZone, nodeIPv4, &runtime, webUIEnabled, publicOrigin, channelIntegrationOrigin, tlsTermination, authServiceOTPDeliveryMode, registry...)
}

func prepareValuesFile(baseValuesPath, profile string, profileCatalog ProfileCatalog, hostAgentImageReference, applianceName, dnsZone, nodeIPv4 string, runtime *runtimeconfig.Selection, webUIEnabled bool, publicOrigin, channelIntegrationOrigin, tlsTermination, authServiceOTPDeliveryMode string, registry ...string) (string, func(), error) {
	effectiveProfile, err := ResolveApplianceProfileWithCatalog(profile, "", profileCatalog)
	if err != nil {
		return "", func() {}, err
	}
	resolvedModules := ResolveModulesWithCatalog(effectiveProfile, profileCatalog, AlwaysEntitled{}, BuiltInModuleCatalog())
	hostAgentEnabled := HostAgentEnabled(resolvedModules)
	artifactEnabled := ModuleEnabled(resolvedModules, ModuleNameArtifactRegistry)
	dnsEnabled := ModuleEnabled(resolvedModules, ModuleNameLANDNS)
	inferenceEnabled := ModuleEnabled(resolvedModules, ModuleNameInferenceRuntime)
	identity, err := ResolveApplianceIdentity(applianceName, dnsZone)
	if err != nil {
		return "", func() {}, err
	}
	publicOrigin, publicOriginHost, tlsTermination, err := normalizePublicOriginAndTLS(publicOrigin, tlsTermination, identity.FQDN)
	if err != nil {
		return "", func() {}, err
	}
	if strings.TrimSpace(channelIntegrationOrigin) == "" {
		channelIntegrationOrigin = publicOrigin
	}
	_, channelIntegrationHost, _, err := normalizePublicOriginAndTLS(channelIntegrationOrigin, tlsTermination, identity.FQDN)
	if err != nil {
		return "", func() {}, fmt.Errorf("product config: channel integration origin: %w", err)
	}
	hostAgentImageReference = strings.TrimSpace(hostAgentImageReference)
	artifactServerImageReference := ""
	blobStorageImageReference := ""
	postgresImageReference := ""
	channelIntegrationImageReference := ""
	orderingImageReference := ""
	applicationIdentityImageReference := ""
	authServiceImageReference := ""
	if len(registry) > 0 {
		artifactServerImageReference = strings.TrimSpace(registry[0])
	}
	if len(registry) > 1 {
		blobStorageImageReference = strings.TrimSpace(registry[1])
	}
	if len(registry) > 2 {
		postgresImageReference = strings.TrimSpace(registry[2])
	}
	if len(registry) > 3 {
		channelIntegrationImageReference = strings.TrimSpace(registry[3])
	}
	if len(registry) > 4 {
		orderingImageReference = strings.TrimSpace(registry[4])
	}
	if len(registry) > 5 {
		applicationIdentityImageReference = strings.TrimSpace(registry[5])
	}
	if len(registry) > 6 {
		authServiceImageReference = strings.TrimSpace(registry[6])
	}
	if artifactEnabled && len(registry) > 0 && !validArtifactServerImageDigest(artifactServerImageReference) {
		return "", func() {}, fmt.Errorf("product config: artifact capability requires bundled registry.local/artifact-server@sha256 image reference; got %q", artifactServerImageReference)
	}
	if !validBlobStorageImageDigest(blobStorageImageReference) {
		return "", func() {}, fmt.Errorf("product config: foundation requires a bundled registry.local/blob-storage@sha256 image reference; got %q", blobStorageImageReference)
	}
	if postgresImageReference != "" && !validPostgresImageDigest(postgresImageReference) {
		return "", func() {}, fmt.Errorf("product config: PostgreSQL image must be registry.local/postgres@sha256:<64>; got %q", postgresImageReference)
	}
	channelIntegrationsEnabled := HasCapabilityInCatalog(effectiveProfile, CapabilityChannelIntegrations, profileCatalog)
	if channelIntegrationsEnabled && !validChannelIntegrationImageDigest(channelIntegrationImageReference) {
		return "", func() {}, fmt.Errorf("product config: channel-integrations capability requires a bundled registry.local/channel-integration@sha256 image reference; got %q", channelIntegrationImageReference)
	}
	commerceEnabled := HasCapabilityInCatalog(effectiveProfile, CapabilityCommerce, profileCatalog)
	if commerceEnabled && !validOrderingImageDigest(orderingImageReference) {
		return "", func() {}, fmt.Errorf("product config: commerce capability requires a bundled registry.local/ordering@sha256 image reference; got %q", orderingImageReference)
	}
	identityEnabled := HasCapabilityInCatalog(effectiveProfile, CapabilityApplicationIdentity, profileCatalog)
	if identityEnabled && !validApplicationIdentityImageDigest(applicationIdentityImageReference) {
		return "", func() {}, fmt.Errorf("product config: application-identity capability requires a bundled registry.local/application-identity@sha256 image reference; got %q", applicationIdentityImageReference)
	}
	authEnabled := HasCapabilityInCatalog(effectiveProfile, CapabilityApplicationAuth, profileCatalog)
	if authEnabled && !validAuthServiceImageDigest(authServiceImageReference) {
		return "", func() {}, fmt.Errorf("product config: application-auth capability requires a bundled registry.local/auth-service@sha256 image reference; got %q", authServiceImageReference)
	}
	authServiceOTPDeliveryMode = strings.ToLower(strings.TrimSpace(authServiceOTPDeliveryMode))
	if authServiceOTPDeliveryMode != "" && authServiceOTPDeliveryMode != "local" && authServiceOTPDeliveryMode != "event" {
		return "", func() {}, fmt.Errorf("product config: auth service OTP delivery mode must be local or event, got %q", authServiceOTPDeliveryMode)
	}
	if authServiceOTPDeliveryMode != "" && !authEnabled {
		return "", func() {}, fmt.Errorf("product config: auth service OTP delivery mode requires the application-auth capability")
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
	config["canonicalOrigin"] = publicOrigin
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
	openWebUIEnabled := inferenceEnabled && webUIEnabled && HasCapabilityInCatalog(effectiveProfile, CapabilityOpenWebUI, profileCatalog)
	config["webUIEnabled"] = openWebUIEnabled
	if openWebUIEnabled {
		config["webUIHealthURL"] = DefaultOpenWebUIHealthURL
	} else {
		delete(config, "webUIHealthURL")
	}
	ingress, _ := values["ingress"].(map[string]any)
	if ingress == nil {
		ingress = map[string]any{}
	}
	ingress["webUIEnabled"] = openWebUIEnabled
	// The public TLS terminator determines how the appliance is reached from
	// outside. Cloudflare terminates HTTPS at the edge and tunnels to the
	// appliance's local HTTP entrypoint; project that existing install setting
	// into the chart so the full UI/API route is available on web as well.
	ingress["tlsTermination"] = tlsTermination
	values["ingress"] = ingress
	if registryConfig := ServiceRegistryConfig(resolvedModules); registryConfig != nil {
		config["serviceRegistry"] = registryConfig
	} else {
		delete(config, "serviceRegistry")
	}
	delete(config, "buildCatalog")
	delete(config, "allowedGitSourceHosts")
	values["config"] = config
	actionRuntime, _ := values["actionRuntime"].(map[string]any)
	if actionRuntime == nil {
		actionRuntime = map[string]any{}
	}
	actionRuntime["enabled"] = HasCapabilityInCatalog(effectiveProfile, CapabilityActions, profileCatalog)
	values["actionRuntime"] = actionRuntime
	channelIntegration, _ := values["channelIntegration"].(map[string]any)
	if channelIntegration == nil {
		channelIntegration = map[string]any{}
	}
	channelIntegration["enabled"] = channelIntegrationsEnabled
	channelIngress, _ := channelIntegration["ingress"].(map[string]any)
	if channelIngress == nil {
		channelIngress = map[string]any{}
	}
	if channelIntegrationsEnabled {
		channelIngress["host"] = channelIntegrationHost
		if tlsTermination == "cloudflare" {
			channelIngress["entryPoints"] = []string{"web"}
			channelIngress["tls"] = map[string]any{"enabled": false}
		} else {
			channelIngress["entryPoints"] = []string{"websecure"}
			channelIngress["tls"] = map[string]any{"enabled": true}
		}
	}
	channelIntegration["ingress"] = channelIngress
	channelImage, _ := channelIntegration["image"].(map[string]any)
	if channelImage == nil {
		channelImage = map[string]any{}
	}
	if channelIntegrationsEnabled {
		channelImage["reference"] = channelIntegrationImageReference
	}
	channelIntegration["image"] = channelImage
	values["channelIntegration"] = channelIntegration
	applicationServices, _ := values["applicationServices"].(map[string]any)
	if applicationServices == nil {
		applicationServices = map[string]any{}
	}
	identityValues, _ := applicationServices["identity"].(map[string]any)
	if identityValues == nil {
		identityValues = map[string]any{}
	}
	if channelIntegrationsEnabled && HasCapabilityInCatalog(effectiveProfile, CapabilityApplicationIdentity, profileCatalog) {
		identityValues["deliveryMode"] = "event"
	} else {
		identityValues["deliveryMode"] = "local"
	}
	applicationServices["identity"] = identityValues
	ordering, _ := applicationServices["ordering"].(map[string]any)
	if ordering == nil {
		ordering = map[string]any{}
	}
	ordering["enabled"] = commerceEnabled
	orderingIngress, _ := ordering["ingress"].(map[string]any)
	if orderingIngress == nil {
		orderingIngress = map[string]any{}
	}
	if commerceEnabled {
		orderingIngress["host"] = publicOriginHost
		if tlsTermination == "cloudflare" {
			orderingIngress["entryPoints"] = []string{"web"}
			orderingIngress["tls"] = map[string]any{"enabled": false}
		} else {
			orderingIngress["entryPoints"] = []string{"websecure"}
			orderingIngress["tls"] = map[string]any{"enabled": true}
		}
	}
	ordering["ingress"] = orderingIngress
	orderingImage, _ := ordering["image"].(map[string]any)
	if orderingImage == nil {
		orderingImage = map[string]any{}
	}
	if commerceEnabled {
		orderingImage["reference"] = orderingImageReference
	}
	ordering["image"] = orderingImage
	identityService, _ := applicationServices["identity"].(map[string]any)
	if identityService == nil {
		identityService = map[string]any{}
	}
	identityService["enabled"] = identityEnabled
	if identityEnabled {
		identityService["origin"] = publicOrigin
	}
	identityImage, _ := identityService["image"].(map[string]any)
	if identityImage == nil {
		identityImage = map[string]any{}
	}
	if identityEnabled {
		identityImage["reference"] = applicationIdentityImageReference
	}
	identityService["image"] = identityImage
	authService, _ := applicationServices["auth"].(map[string]any)
	if authService == nil {
		authService = map[string]any{}
	}
	authService["enabled"] = authEnabled
	if identityEnvironment, ok := identityService["environment"].(string); ok && identityEnvironment != "" {
		authService["environment"] = identityEnvironment
	}
	if identityOrigin, ok := identityService["origin"].(string); ok && identityOrigin != "" {
		authService["origin"] = identityOrigin
	}
	if authEnabled {
		if authServiceOTPDeliveryMode == "" {
			authServiceOTPDeliveryMode = "event"
		}
		authService["deliveryMode"] = authServiceOTPDeliveryMode
	}
	authImage, _ := authService["image"].(map[string]any)
	if authImage == nil {
		authImage = map[string]any{}
	}
	authImage["reference"] = authServiceImageReference
	authService["image"] = authImage
	applicationServices["auth"] = authService
	applicationServices["identity"] = identityService
	applicationServices["ordering"] = ordering
	values["applicationServices"] = applicationServices
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
	if postgresImageReference != "" {
		database, _ := values["database"].(map[string]any)
		if database == nil {
			database = map[string]any{}
		}
		database["driver"] = "postgres"
		database["maxOpenConns"] = 12
		database["maxIdleConns"] = 4
		database["connMaxLifetime"] = "30m"
		postgres, _ := database["postgres"].(map[string]any)
		if postgres == nil {
			postgres = map[string]any{}
		}
		postgres["connectionSecretName"] = "controlplane-database-connection"
		local, _ := postgres["local"].(map[string]any)
		if local == nil {
			local = map[string]any{}
		}
		local["enabled"] = true
		image, _ := local["image"].(map[string]any)
		if image == nil {
			image = map[string]any{}
		}
		image["repository"] = "registry.local/postgres"
		image["digest"] = strings.TrimPrefix(postgresImageReference, "registry.local/postgres@")
		image["pullPolicy"] = "IfNotPresent"
		local["image"] = image
		postgres["local"] = local
		database["postgres"] = postgres
		values["database"] = database
	}

	// controlplane lives in the Helm release namespace (zonctl defaultChartNamespace =
	// ace-system). Co-packaged apps go in ace-apps.
	values["namespace"] = map[string]any{"create": false}
	values["appsNamespace"] = map[string]any{
		"create": false,
		"name":   ControlPlaneAppsNamespace,
	}
	values["appCoreNamespace"] = map[string]any{
		"create": false,
		"name":   ApplicationCoreNamespace,
	}
	// Default empty: lab install injects appliance-image-pull via
	// InjectImagePullSecrets when --image-pull-registry is set.
	if _, has := values["imagePullSecrets"]; !has {
		values["imagePullSecrets"] = []any{}
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
	if channelIntegrationsEnabled {
		// The channel webhook is exposed through the K3s-managed Traefik
		// namespace. Keep this allow-list capability-scoped; other profiles
		// remain ingress-denied by default.
		networkPolicy["traefikNamespaceLabel"] = map[string]any{
			"kubernetes.io/metadata.name": "kube-system",
		}
	}
	if artifactEnabled || dnsEnabled || inferenceEnabled || channelIntegrationsEnabled {
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

// InjectPlacementNodeName pins hostPath and hostNetwork workloads to the
// advertised prime Kubernetes node name via chart nodeSelector (not
// spec.nodeName, which would skip the scheduler and leave WaitForFirstConsumer
// PVCs unbound). No-op when nodeName is empty.
func InjectPlacementNodeName(valuesPath, nodeName string) error {
	nodeName = strings.TrimSpace(nodeName)
	if nodeName == "" {
		return nil
	}
	data, err := os.ReadFile(valuesPath)
	if err != nil {
		return fmt.Errorf("product config: read values for placement: %w", err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("product config: parse values for placement: %w", err)
	}
	if values == nil {
		values = map[string]any{}
	}
	values["placement"] = map[string]any{"nodeName": nodeName}
	rendered, err := yaml.Marshal(values)
	if err != nil {
		return fmt.Errorf("product config: render placement values: %w", err)
	}
	if err := os.WriteFile(valuesPath, rendered, 0o600); err != nil {
		return fmt.Errorf("product config: write placement values: %w", err)
	}
	return nil
}

// PreparePlacementValuesFile writes a tiny values overlay that pins a chart
// to the advertised prime.
func PreparePlacementValuesFile(baseDir, nodeName string) (string, func(), error) {
	nodeName = strings.TrimSpace(nodeName)
	values := map[string]any{}
	if nodeName != "" {
		values["placement"] = map[string]any{"nodeName": nodeName}
	}
	rendered, err := yaml.Marshal(values)
	if err != nil {
		return "", func() {}, fmt.Errorf("product config: render placement values: %w", err)
	}
	tmp, err := os.CreateTemp(baseDir, ".zonctl-placement-values-*.yaml")
	if err != nil {
		return "", func() {}, fmt.Errorf("product config: create placement values file: %w", err)
	}
	cleanup := func() { _ = os.Remove(tmp.Name()) }
	if _, err := tmp.Write(rendered); err != nil {
		tmp.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("product config: write placement values file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("product config: close placement values file: %w", err)
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

// InjectTLSSecretName rewrites the prepared control-plane values so every
// Traefik ingress uses the same installer-provided TLS Secret. Empty names
// retain the chart default (appliance-tls).
func InjectTLSSecretName(valuesPath, secretName string) error {
	secretName = strings.TrimSpace(secretName)
	if secretName == "" {
		return nil
	}
	if len(secretName) > 253 || !regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`).MatchString(secretName) {
		return fmt.Errorf("product config: invalid TLS Secret name %q", secretName)
	}
	data, err := os.ReadFile(valuesPath)
	if err != nil {
		return fmt.Errorf("product config: read values for TLS Secret: %w", err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("product config: parse values for TLS Secret: %w", err)
	}
	if values == nil {
		values = map[string]any{}
	}
	ingress, _ := values["ingress"].(map[string]any)
	if ingress == nil {
		ingress = map[string]any{}
	}
	ingress["tlsSecretName"] = secretName
	values["ingress"] = ingress
	channel, _ := values["channelIntegration"].(map[string]any)
	if channel == nil {
		channel = map[string]any{}
	}
	channelIngress, _ := channel["ingress"].(map[string]any)
	if channelIngress == nil {
		channelIngress = map[string]any{}
	}
	channelIngress["tlsSecretName"] = secretName
	channel["ingress"] = channelIngress
	values["channelIntegration"] = channel
	rendered, err := yaml.Marshal(values)
	if err != nil {
		return fmt.Errorf("product config: render TLS Secret values: %w", err)
	}
	if err := os.WriteFile(valuesPath, rendered, 0o600); err != nil {
		return fmt.Errorf("product config: write TLS Secret values: %w", err)
	}
	return nil
}

// InjectRegistryTLSSecretName rewrites the artifact-server values overlay. The
// registry chart has its own values document and does not accept the
// control-plane channelIntegration subtree.
func InjectRegistryTLSSecretName(valuesPath, secretName string) error {
	secretName = strings.TrimSpace(secretName)
	if secretName == "" {
		return nil
	}
	if len(secretName) > 253 || !regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`).MatchString(secretName) {
		return fmt.Errorf("product config: invalid TLS Secret name %q", secretName)
	}
	data, err := os.ReadFile(valuesPath)
	if err != nil {
		return fmt.Errorf("product config: read registry values for TLS Secret: %w", err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("product config: parse registry values for TLS Secret: %w", err)
	}
	if values == nil {
		values = map[string]any{}
	}
	ingress, _ := values["ingress"].(map[string]any)
	if ingress == nil {
		ingress = map[string]any{}
	}
	ingress["tlsSecretName"] = secretName
	values["ingress"] = ingress
	rendered, err := yaml.Marshal(values)
	if err != nil {
		return fmt.Errorf("product config: render registry TLS Secret values: %w", err)
	}
	if err := os.WriteFile(valuesPath, rendered, 0o600); err != nil {
		return fmt.Errorf("product config: write registry TLS Secret values: %w", err)
	}
	return nil
}

// InjectBootstrapConfigurationSecret enables the one-shot control-plane
// payload mount used only by a restore-config install.
func InjectBootstrapConfigurationSecret(valuesPath, secretName string) error {
	secretName = strings.TrimSpace(secretName)
	if secretName == "" {
		return nil
	}
	data, err := os.ReadFile(valuesPath)
	if err != nil {
		return fmt.Errorf("product config: read values for bootstrap configuration: %w", err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("product config: parse values for bootstrap configuration: %w", err)
	}
	if values == nil {
		values = map[string]any{}
	}
	secrets, _ := values["secrets"].(map[string]any)
	if secrets == nil {
		secrets = map[string]any{}
	}
	secrets["bootstrapConfigurationSecretName"] = secretName
	values["secrets"] = secrets
	rendered, err := yaml.Marshal(values)
	if err != nil {
		return fmt.Errorf("product config: render bootstrap configuration values: %w", err)
	}
	if err := os.WriteFile(valuesPath, rendered, 0o600); err != nil {
		return fmt.Errorf("product config: write bootstrap configuration values: %w", err)
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
	return PrepareInferenceValuesFileForNode(baseDir, inferenceRuntimeImageReference, inferenceManagerImageReference, openWebUIImageReference, openWebUIGatewayImageReference, runtime, "")
}

// PrepareInferenceValuesFileForNode binds the initial inference release to the
// appliance node name. The Kubernetes scheduler later resolves that
// controller-owned name back to the node UID; unlike a UID it is available
// before the first K3s API server has started.
func PrepareInferenceValuesFileForNode(baseDir, inferenceRuntimeImageReference, inferenceManagerImageReference, openWebUIImageReference, openWebUIGatewayImageReference string, runtime runtimeconfig.Selection, nodeName string) (string, func(), error) {
	return prepareInferenceValuesFile(baseDir, inferenceRuntimeImageReference, inferenceManagerImageReference, openWebUIImageReference, openWebUIGatewayImageReference, runtime, hostNVIDIACheck(), nodeName)
}

func prepareInferenceValuesFile(baseDir, inferenceRuntimeImageReference, inferenceManagerImageReference, openWebUIImageReference, openWebUIGatewayImageReference string, runtime runtimeconfig.Selection, gpuAvailable bool, nodeName string) (string, func(), error) {
	if strings.TrimSpace(nodeName) != "" {
		if err := validateInferenceNodeName(nodeName); err != nil {
			return "", func() {}, fmt.Errorf("product config: invalid inference node name %q", nodeName)
		}
	}
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
		"routing": map[string]any{
			"registryName": DefaultInferenceRoutingRegistry,
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
	if strings.TrimSpace(nodeName) != "" {
		values["placement"] = map[string]any{"nodeName": strings.TrimSpace(nodeName)}
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

// PrepareNodeInferenceValuesFile produces the controller-owned values for one
// inference node. Names and placement come from verified cluster inventory;
// callers must never pass these values through from an end user.
func PrepareNodeInferenceValuesFile(baseDir, inferenceRuntimeImageReference, inferenceManagerImageReference string, runtime runtimeconfig.Selection, nodeName, nodeUID string) (string, func(), error) {
	if err := validateInferenceNodeName(nodeName); err != nil {
		return "", func() {}, fmt.Errorf("product config: invalid inference node name %q", nodeName)
	}
	if strings.TrimSpace(nodeUID) == "" {
		return "", func() {}, fmt.Errorf("product config: inference node UID is required")
	}
	// The joining node has already validated an accelerated runtime locally.
	// Do not probe the control-plane host while rendering its remote release.
	path, cleanup, err := prepareInferenceValuesFile(baseDir, inferenceRuntimeImageReference, inferenceManagerImageReference, "", "", runtime, runtimeconfig.RequiresGPU(runtime), nodeName)
	if err != nil {
		return "", cleanup, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	var values map[string]any
	if err := yaml.Unmarshal(raw, &values); err != nil {
		cleanup()
		return "", func() {}, err
	}
	resourceNodeName := inferenceNodeResourceSuffix(nodeName)
	values["placement"] = map[string]any{"nodeName": nodeName, "nodeUID": nodeUID, "requireInferenceNode": true}
	values["fullnameOverride"] = "inference-node-" + resourceNodeName
	values["engine"] = map[string]any{"serviceName": "inference-engine-" + resourceNodeName}
	values["persistence"] = map[string]any{"claimName": "models-" + resourceNodeName}
	values["routing"] = map[string]any{"registryName": DefaultInferenceRoutingRegistry}
	values["openWebUI"] = map[string]any{"enabled": false}
	updated, err := yaml.Marshal(values)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	if err := os.WriteFile(path, updated, 0o600); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

// InferenceNodeReleaseName returns the controller-owned Helm release identity
// for a registered node. It is shared by deployment and removal so they can
// never disagree about which release owns node-local storage.
func InferenceNodeReleaseName(nodeName string) (string, error) {
	if err := validateInferenceNodeName(nodeName); err != nil {
		return "", err
	}
	return "inference-node-" + inferenceNodeResourceSuffix(nodeName), nil
}

func validateInferenceNodeName(nodeName string) error {
	if len(nodeName) > 63 || !dnsLabelRE.MatchString(nodeName) {
		return fmt.Errorf("invalid inference node name %q", nodeName)
	}
	return nil
}

// inferenceNodeResourceSuffix bounds all derived Kubernetes names while
// retaining a stable collision-resistant identity for a legal 63-character
// node name. The shortest consumer prefix is not the constraint; engine
// Service names are ("inference-engine-" + 46 chars == 63).
func inferenceNodeResourceSuffix(nodeName string) string {
	const max = 46
	if len(nodeName) <= max {
		return nodeName
	}
	digest := sha256.Sum256([]byte(nodeName))
	return nodeName[:max-9] + "-" + fmt.Sprintf("%x", digest[:4])
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

func validPostgresImageDigest(image string) bool {
	image = strings.TrimSpace(image)
	if !strings.HasPrefix(image, "registry.local/postgres@sha256:") || !sha256ImageDigestRE.MatchString(image) {
		return false
	}
	return strings.TrimPrefix(image, "registry.local/postgres@sha256:") != placeholderImageDigestHex
}

func validChannelIntegrationImageDigest(image string) bool {
	return validRegistryLocalImageDigest(image, "channel-integration")
}

func validOrderingImageDigest(image string) bool {
	return validRegistryLocalImageDigest(image, "ordering")
}

func validApplicationIdentityImageDigest(image string) bool {
	return validRegistryLocalImageDigest(image, "application-identity")
}

func validAuthServiceImageDigest(image string) bool {
	return validRegistryLocalImageDigest(image, "auth-service")
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
