package productconfig_test

import (
	"github.com/zoncaesaradmin/appliance-ctl/internal/runtimeconfig"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
)

const (
	workspaceProvisionerImage = "registry.local/workspace-provisioner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	builderImage              = "registry.local/dev-build@sha256:5ccdfda08e940614d030e377b75f048a55e3f61cbb0234294ad333f27afe222c"
	hostAgentImage            = "registry.local/appliance-host-agent@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	artifactServerImage       = "registry.local/artifact-server@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	corednsImage              = "registry.local/coredns@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	inferenceRuntimeImage     = "registry.local/inference-runtime@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	inferenceManagerImage     = "registry.local/inference-manager@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	openWebUIImage            = "registry.local/open-webui@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	openWebUIGatewayImage     = "registry.local/open-webui-gateway@sha256:2222222222222222222222222222222222222222222222222222222222222222"
	blobStorageImage          = "registry.local/blob-storage@sha256:abababababababababababababababababababababababababababababababab"
)

func TestPrepareValuesFile_ArtifactCapabilityInjectsRegistryConfig(t *testing.T) {
	valuesPath := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	rendered, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileStorage, testProfileCatalog(), "", "", hostAgentImage, "registry1", "appliance.internal", "192.0.2.10", artifactServerImage, blobStorageImage)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(rendered)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"applianceProfile: storage",
		"canonicalOrigin: https://registry1.appliance.internal",
		"applianceName: registry1",
		"dnsZoneName: appliance.internal",
		"nodeIPv4: 192.0.2.10",
		"name: host-agent",
		"capability: host",
		"baseURL: http://host-agent.ace-apps.svc.cluster.local:8080",
		"name: ace-apps", // appsNamespace
		"externalPath: /api/v1/host/info",
		"externalPath: /api/v1/host/stats",
		"externalPath: /api/v1/host/health",
		"reference: " + hostAgentImage,
		"artifactServerBaseURL:",
		"kubernetes.io/metadata.name: artifacts",
		"app.kubernetes.io/name: appliance-registry",
		"endpoint: http://blob-storage.ace-infra.svc.cluster.local:9000",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered values missing %q:\n%s", want, text)
		}
	}
}

func TestPrepareValuesFile_DNSCapabilityInjectsReadyURL(t *testing.T) {
	valuesPath := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	rendered, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileLANDNS, testProfileCatalog(), "", "", hostAgentImage, "dns1", "appliance.internal", "192.0.2.10", "", blobStorageImage)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(rendered)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"applianceProfile: landns",
		"applianceName: dns1",
		"dnsZoneName: appliance.internal",
		"canonicalOrigin: https://dns1.appliance.internal",
		"dnsReadyURL: " + productconfig.DefaultDNSReadyURL,
		"dnsZoneName: " + productconfig.DefaultLANDNSZone,
		"dnsAllowFakeZoneSync: false",
		"kubernetes.io/metadata.name: dns",
		"app.kubernetes.io/name: dns-server",
		"dnsReadyPort: 8181",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered values missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "artifactServerBaseURL:") {
		t.Fatalf("landns must not inject artifactServerBaseURL:\n%s", text)
	}
	for _, forbidden := range []string{
		"dnsBootstrapHostname: appliance",
		"dnsBootstrapIPv4: 192.0.2.10",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("landns must not seed DNS A records from public_host (%q present):\n%s", forbidden, text)
		}
	}
}

func TestPrepareValuesFileForRuntime_EnablesWebUIOnlyForInferencePackPair(t *testing.T) {
	valuesPath := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config: {}\ningress: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	runtime := runtimeconfig.Selection{Package: "std-llm", InferenceEngine: "ollama", Architecture: "amd64"}
	rendered, cleanup, err := productconfig.PrepareValuesFileForRuntime(valuesPath, productconfig.ProfileLANLLM, testProfileCatalog(), "", "", "", "llm1", "appliance.internal", "", runtime, true, "", blobStorageImage)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(rendered)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "webUIEnabled: true") {
		t.Fatalf("complete inference image pair must enable the control-plane and route flags:\n%s", text)
	}

	disabled, disabledCleanup, err := productconfig.PrepareValuesFileForRuntime(valuesPath, productconfig.ProfileLANLLM, testProfileCatalog(), "", "", "", "llm1", "appliance.internal", "", runtime, false, "", blobStorageImage)
	if err != nil {
		t.Fatal(err)
	}
	defer disabledCleanup()
	disabledData, err := os.ReadFile(disabled)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(disabledData), "webUIEnabled: true") {
		t.Fatalf("missing WebUI image pair must not expose the route:\n%s", disabledData)
	}
}

func TestPrepareDNSValuesFile_DigestPinAndLocalZone(t *testing.T) {
	path, cleanup, err := productconfig.PrepareDNSValuesFile(t.TempDir(), corednsImage, "appliance.internal", "192.0.2.10", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"digest: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		"hostNetwork: true",
		"hostname: \"\"",
		"ipv4: 192.0.2.10",
		"name: appliance.internal",
		"hostPath: /data/zon/logs/dns",
		"- 1.1.1.1",
		"create: false",
		"name: dns",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered dns values missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "hostname: appliance") {
		t.Fatalf("dns values must not seed a product hostname:\n%s", text)
	}
}

func TestPrepareRegistryValuesFile_DigestPinAndPersistence(t *testing.T) {
	path, cleanup, err := productconfig.PrepareRegistryValuesFile(t.TempDir(), artifactServerImage, "registry1.appliance.internal")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") ||
		!strings.Contains(text, "repository: registry.local/artifact-server") ||
		!strings.Contains(text, "accessMode: ReadWriteOnce") ||
		!strings.Contains(text, productconfig.DefaultRegistryPublicKeySecret) ||
		!strings.Contains(text, "kubernetes.io/metadata.name: ace-system") ||
		!strings.Contains(text, "app.kubernetes.io/name: controlplane") ||
		!strings.Contains(text, "hostPath: /data/zon/logs/artifactserver") {
		t.Fatalf("unexpected registry values:\n%s", text)
	}
	for _, forbidden := range []string{"fileserver", "registry.local/fileserver", "/data/zon/logs/fileserver", "/data/zon/files"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("registry values unexpectedly contain removed fileserver surface %q:\n%s", forbidden, text)
		}
	}
}
func TestPrepareRegistryValuesFile_UsesApplianceFQDN(t *testing.T) {
	path, cleanup, err := productconfig.PrepareRegistryValuesFile(t.TempDir(), artifactServerImage, "registry1.appliance.internal")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "realm: https://registry1.appliance.internal/api/v1/registry/token") {
		t.Fatalf("rendered registry values missing realm override:\n%s", text)
	}
	if strings.Contains(text, "host: appliance.internal.example.com") {
		t.Fatalf("registry ingress host should remain empty by default so /v2 matches appliance IP access too:\n%s", text)
	}
}

func TestPrepareInferenceValuesFile_DigestPinOnly(t *testing.T) {
	restore := productconfig.OverrideHostNVIDIACheckForTest(func() bool { return false })
	defer restore()
	path, cleanup, err := productconfig.PrepareInferenceValuesFile(t.TempDir(), inferenceRuntimeImage, inferenceManagerImage, openWebUIImage, openWebUIGatewayImage, runtimeconfig.Selection{Package: "std-llm", InferenceEngine: "ollama", Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "repository: registry.local/inference-runtime") ||
		!strings.Contains(text, "digest: sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee") ||
		!strings.Contains(text, "repository: registry.local/inference-manager") ||
		!strings.Contains(text, "digest: sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") ||
		!strings.Contains(text, "enabled: true") ||
		!strings.Contains(text, "repository: registry.local/open-webui") ||
		!strings.Contains(text, "digest: sha256:1111111111111111111111111111111111111111111111111111111111111111") ||
		!strings.Contains(text, "repository: registry.local/open-webui-gateway") ||
		!strings.Contains(text, "digest: sha256:2222222222222222222222222222222222222222222222222222222222222222") ||
		!strings.Contains(text, "name: inference") ||
		!strings.Contains(text, "create: false") || !strings.Contains(text, "engine: ollama") ||
		!strings.Contains(text, "gpu:\n    driverCapabilities: all\n    enabled: false") {
		t.Fatalf("unexpected inference values:\n%s", text)
	}
	for _, forbidden := range []string{
		"hostPath:",
		"/data/zon/logs/inference",
		"/data/zon/inference/models",
		"persistence:",
		"mode:",
		"supportedModes:",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("inference values unexpectedly contain %q:\n%s", forbidden, text)
		}
	}
}

func TestPrepareInferenceValuesFile_AcceleratedRequiresGPU(t *testing.T) {
	restore := productconfig.OverrideHostNVIDIACheckForTest(func() bool { return false })
	defer restore()
	_, cleanup, err := productconfig.PrepareInferenceValuesFile(t.TempDir(), inferenceRuntimeImage, inferenceManagerImage, openWebUIImage, openWebUIGatewayImage, runtimeconfig.Selection{
		Package: "acc-llm", InferenceEngine: "vllm", Architecture: "arm64",
	})
	cleanup()
	if err == nil || !strings.Contains(err.Error(), "requires a usable GPU") {
		t.Fatalf("accelerated pack without GPU error=%v", err)
	}
}

func TestHostNVIDIAAvailable_UsesOverride(t *testing.T) {
	restore := productconfig.OverrideHostNVIDIACheckForTest(func() bool { return true })
	defer restore()
	if !productconfig.HostNVIDIAAvailable() {
		t.Fatal("expected override true")
	}
	restore2 := productconfig.OverrideHostNVIDIACheckForTest(func() bool { return false })
	defer restore2()
	if productconfig.HostNVIDIAAvailable() {
		t.Fatal("expected override false")
	}
}

func TestPrepareInferenceValuesFile_AcceleratedEnablesGPU(t *testing.T) {
	restore := productconfig.OverrideHostNVIDIACheckForTest(func() bool { return true })
	defer restore()
	path, cleanup, err := productconfig.PrepareInferenceValuesFile(t.TempDir(), inferenceRuntimeImage, inferenceManagerImage, openWebUIImage, openWebUIGatewayImage, runtimeconfig.Selection{
		Package: "acc-llm", InferenceEngine: "vllm", Architecture: "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "engine: vllm") || !strings.Contains(text, "gpu:\n    driverCapabilities: all\n    enabled: true") {
		t.Fatalf("accelerated values must enable GPU:\n%s", text)
	}
	for _, forbidden := range []string{"mode:", "supportedModes:"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("inference values unexpectedly contain %q:\n%s", forbidden, text)
		}
	}
}

func TestResolveApplianceIdentity(t *testing.T) {
	identity, err := productconfig.ResolveApplianceIdentity("Registry1", "")
	if err != nil {
		t.Fatalf("ResolveApplianceIdentity: %v", err)
	}
	if identity.Name != "registry1" || identity.Zone != productconfig.DefaultLANDNSZone || identity.FQDN != "registry1.appliance.internal" {
		t.Fatalf("identity = %+v", identity)
	}
	if _, err := productconfig.ResolveApplianceIdentity("bad.name", "appliance.internal"); err == nil {
		t.Fatal("expected multi-label appliance name to fail")
	}
	if _, err := productconfig.ResolveApplianceIdentity("dns1", "appliance.local"); err == nil {
		t.Fatal("expected .local zone to fail")
	}
}

func TestSelectApplianceProfile_DefaultsToCore(t *testing.T) {
	profile := productconfig.SelectApplianceProfile("", "")
	if profile != productconfig.ProfileCore {
		t.Fatalf("profile = %q, want %q", profile, productconfig.ProfileCore)
	}
}

func TestResolveApplianceProfileWithCatalog_DefaultsToCore(t *testing.T) {
	profile, err := productconfig.ResolveApplianceProfileWithCatalog("", "", testProfileCatalog())
	if err != nil {
		t.Fatalf("ResolveApplianceProfileWithCatalog returned error: %v", err)
	}
	if profile != productconfig.ProfileCore {
		t.Fatalf("profile = %q, want %q", profile, productconfig.ProfileCore)
	}
}

func TestResolveApplianceProfileWithCatalog_PreservesCurrentWhenRequestedEmpty(t *testing.T) {
	profile, err := productconfig.ResolveApplianceProfileWithCatalog("", productconfig.ProfileStorage, testProfileCatalog())
	if err != nil {
		t.Fatalf("ResolveApplianceProfileWithCatalog returned error: %v", err)
	}
	if profile != productconfig.ProfileStorage {
		t.Fatalf("profile = %q, want %q", profile, productconfig.ProfileStorage)
	}
}

func TestResolveApplianceProfileWithCatalog_AcceptsLANDNSProfiles(t *testing.T) {
	catalog := testProfileCatalog()
	for _, requested := range []string{"landns", "storage-landns", "builder-landns", "builder-storage-landns"} {
		t.Run(requested, func(t *testing.T) {
			profile, err := productconfig.ResolveApplianceProfileWithCatalog(requested, "", catalog)
			if err != nil {
				t.Fatalf("ResolveApplianceProfileWithCatalog(%q) returned error: %v", requested, err)
			}
			if profile != requested {
				t.Fatalf("profile = %q, want %q", profile, requested)
			}
			if !productconfig.HasCapabilityInCatalog(profile, productconfig.CapabilityDNS, catalog) {
				t.Fatal("expected dns capability")
			}
		})
	}
}

func TestResolveApplianceProfileWithCatalogUsesProvidedCatalog(t *testing.T) {
	catalog := productconfig.ProfileCatalog{
		"custom": {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityHost}},
	}
	profile, err := productconfig.ResolveApplianceProfileWithCatalog("custom", "", catalog)
	if err != nil {
		t.Fatalf("ResolveApplianceProfileWithCatalog(custom): %v", err)
	}
	if profile != "custom" {
		t.Fatalf("profile = %q, want custom", profile)
	}
	if !productconfig.HasCapabilityInCatalog(profile, productconfig.CapabilityHost, catalog) {
		t.Fatal("custom profile should enable host")
	}
}

func TestResolveApplianceProfileWithCatalog_RejectsUnknownProfile(t *testing.T) {
	if _, err := productconfig.ResolveApplianceProfileWithCatalog("unknown", "", testProfileCatalog()); err == nil {
		t.Fatal("expected unknown profile to fail validation")
	}
}

func TestPrepareValuesFile_InjectsApplianceProfile(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("replicaCount: 1\nsecrets:\n  keysSecretName: appliance-keys\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	preparedPath, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, testProfileCatalog(), workspaceProvisionerImage, builderImage, hostAgentImage, "testapp", productconfig.DefaultLANDNSZone, "", artifactServerImage, blobStorageImage)
	defer cleanup()
	if err != nil {
		t.Fatalf("PrepareValuesFile returned error: %v", err)
	}
	prepared, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(prepared)
	if !strings.Contains(text, "applianceProfile: builder") {
		t.Fatalf("prepared values missing applianceProfile override: %s", text)
	}
	if !strings.Contains(text, "keysSecretName: appliance-keys") {
		t.Fatalf("prepared values lost existing content: %s", text)
	}
}

func TestPrepareValuesFile_UsesMetadataProfileCatalog(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config:\n  applianceProfile: core\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	catalog := productconfig.ProfileCatalog{
		"custom": {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityHost}},
	}

	preparedPath, cleanup, err := productconfig.PrepareValuesFile(valuesPath, "custom", catalog, "", "", hostAgentImage, "testapp", productconfig.DefaultLANDNSZone, "", "", blobStorageImage)
	defer cleanup()
	if err != nil {
		t.Fatalf("PrepareValuesFile returned error: %v", err)
	}
	prepared, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(prepared)
	if !strings.Contains(text, "applianceProfile: custom") {
		t.Fatalf("prepared values missing custom profile override: %s", text)
	}
	if strings.Contains(text, "applianceCatalog:") {
		t.Fatalf("prepared values must not inject applianceCatalog: %s", text)
	}
}

func TestPrepareValuesFile_ApplicationCapabilityEnablesLifecycle(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	catalog := productconfig.ProfileCatalog{
		"media": {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityApplications}},
	}

	preparedPath, cleanup, err := productconfig.PrepareValuesFile(valuesPath, "media", catalog, "", "", hostAgentImage, "testapp", productconfig.DefaultLANDNSZone, "", "", blobStorageImage)
	defer cleanup()
	if err != nil {
		t.Fatalf("PrepareValuesFile returned error: %v", err)
	}
	prepared, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(prepared), "enabledCapabilities:") || !strings.Contains(string(prepared), "- applications") {
		t.Fatalf("application capability must be projected into chart values:\n%s", prepared)
	}
}

func TestPrepareValuesFile_PlaintextHTTPProjectsCapability(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	catalog := productconfig.ProfileCatalog{
		"lan-kiosk": {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityPlaintextHTTP}},
	}

	preparedPath, cleanup, err := productconfig.PrepareValuesFile(valuesPath, "lan-kiosk", catalog, "", "", "", "testapp", productconfig.DefaultLANDNSZone, "", "", blobStorageImage)
	defer cleanup()
	if err != nil {
		t.Fatalf("PrepareValuesFile returned error: %v", err)
	}
	prepared, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(prepared), "- plaintext-http") {
		t.Fatalf("plaintext-http capability must be projected into chart values:\n%s", prepared)
	}
}

func TestPrepareValuesFile_RejectsPlaceholderWorkspaceProvisionerImageDigest(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config:\n  applianceProfile: core\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	_, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, testProfileCatalog(), "registry.local/workspace-provisioner@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", builderImage, hostAgentImage, "testapp", productconfig.DefaultLANDNSZone, "", "", blobStorageImage)
	defer cleanup()
	if err == nil {
		t.Fatal("expected placeholder workspace provisioner image digest to be rejected")
	}
	if !strings.Contains(err.Error(), "workspace provisioner image") {
		t.Fatalf("error = %v, want placeholder digest validation failure", err)
	}
}

func TestPrepareValuesFile_LeavesEmptyBuildCatalogForBuildProfile(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config:\n  buildCatalog: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	path, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilderLANDNS, testProfileCatalog(), workspaceProvisionerImage, builderImage, hostAgentImage, "testapp", productconfig.DefaultLANDNSZone, "", artifactServerImage, blobStorageImage)
	defer cleanup()
	if err != nil {
		t.Fatalf("PrepareValuesFile for builder profile: %v", err)
	}
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(text), "buildCatalog:") {
		t.Fatalf("prepared values missing empty buildCatalog:\n%s", text)
	}
}

func TestInferenceValuesRejectUnsupportedRuntime(t *testing.T) {
	for _, runtime := range []runtimeconfig.Selection{{}, {Package: "std-llm", InferenceEngine: "vllm", Architecture: "amd64"}, {Package: "acc-llm", InferenceEngine: "ollama", Architecture: "arm64"}} {
		_, cleanup, err := productconfig.PrepareInferenceValuesFile(t.TempDir(), inferenceRuntimeImage, inferenceManagerImage, openWebUIImage, openWebUIGatewayImage, runtime)
		cleanup()
		if err == nil {
			t.Fatalf("unsupported runtime accepted: %+v", runtime)
		}
	}
}
