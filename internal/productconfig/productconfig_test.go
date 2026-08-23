package productconfig_test

import (
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
)

func TestRequiredPacks(t *testing.T) {
	cases := []struct {
		profile string
		want    []string
	}{
		{productconfig.ProfileCore, nil},
		{productconfig.ProfileStorage, nil},
		{productconfig.ProfileLANDNS, nil},
		{productconfig.ProfileStorageLANDNS, nil},
		{productconfig.ProfileTraining, []string{"video"}},
		{productconfig.ProfileLANLLM, []string{"inference"}},
		{productconfig.ProfileBuilder, []string{"developer"}},
		{productconfig.ProfileBuilderLANDNS, []string{"developer"}},
		{productconfig.ProfileBuilderLANLLM, []string{"developer", "inference"}},
		{productconfig.ProfileBuilderLANLLMStorageLANDNS, []string{"developer", "inference"}},
	}
	for _, tc := range cases {
		got := productconfig.RequiredPacks(tc.profile)
		if len(got) != len(tc.want) {
			t.Fatalf("RequiredPacks(%q)=%v, want %v", tc.profile, got, tc.want)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Fatalf("RequiredPacks(%q)=%v, want %v", tc.profile, got, tc.want)
			}
		}
	}
}

func TestPrepareValuesFile_ArtifactCapabilityInjectsRegistryConfig(t *testing.T) {
	valuesPath := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	rendered, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileStorage, "", "", "", hostAgentImage, "registry1", "appliance.internal", "192.0.2.10", artifactServerImage)
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
	rendered, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileLANDNS, "", "", "", hostAgentImage, "dns1", "appliance.internal", "192.0.2.10")
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
	path, cleanup, err := productconfig.PrepareInferenceValuesFile(t.TempDir(), inferenceRuntimeImage)
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
		!strings.Contains(text, "name: inference") ||
		!strings.Contains(text, "create: false") {
		t.Fatalf("unexpected inference values:\n%s", text)
	}
	// Chart owns persistence defaults (static hostPath PV+PVC). Installer
	// values must not inject a pod-level hostPath or unused logs block.
	for _, forbidden := range []string{
		"hostPath:",
		"/data/zon/logs/inference",
		"/data/zon/inference/models",
		"persistence:",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("inference values unexpectedly contain %q:\n%s", forbidden, text)
		}
	}
}

func TestPrepareVideoValuesFile_DigestPinOnly(t *testing.T) {
	videoRuntimeImage := "registry.local/video-runtime@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	path, cleanup, err := productconfig.PrepareVideoValuesFile(t.TempDir(), videoRuntimeImage)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "repository: registry.local/video-runtime") ||
		!strings.Contains(text, "digest: sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") ||
		!strings.Contains(text, "name: video") ||
		!strings.Contains(text, "create: false") {
		t.Fatalf("unexpected video values:\n%s", text)
	}
	for _, forbidden := range []string{
		"hostPath:",
		"/data/zon/logs/video",
		"/data/zon/video/library",
		"persistence:",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("video values unexpectedly contain %q:\n%s", forbidden, text)
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

func TestResolveApplianceProfile_DefaultsToCore(t *testing.T) {
	profile, err := productconfig.ResolveApplianceProfile("", "")
	if err != nil {
		t.Fatalf("ResolveApplianceProfile returned error: %v", err)
	}
	if profile != productconfig.ProfileCore {
		t.Fatalf("profile = %q, want %q", profile, productconfig.ProfileCore)
	}
}

func TestResolveApplianceProfile_PreservesCurrentWhenRequestedEmpty(t *testing.T) {
	profile, err := productconfig.ResolveApplianceProfile("", productconfig.ProfileStorage)
	if err != nil {
		t.Fatalf("ResolveApplianceProfile returned error: %v", err)
	}
	if profile != productconfig.ProfileStorage {
		t.Fatalf("profile = %q, want %q", profile, productconfig.ProfileStorage)
	}
}

func TestResolveApplianceProfile_AcceptsLANDNSProfiles(t *testing.T) {
	for _, requested := range []string{"landns", "storage-landns", "builder-landns", "builder-storage-landns"} {
		t.Run(requested, func(t *testing.T) {
			profile, err := productconfig.ResolveApplianceProfile(requested, "")
			if err != nil {
				t.Fatalf("ResolveApplianceProfile(%q) returned error: %v", requested, err)
			}
			if profile != requested {
				t.Fatalf("profile = %q, want %q", profile, requested)
			}
			wantDNS := true
			if productconfig.HasCapability(profile, productconfig.CapabilityDNS) != wantDNS {
				t.Fatalf("HasCapability(dns) = %v, want %v", !wantDNS, wantDNS)
			}
		})
	}
}

func TestBuiltInProfileCatalogReturnsClone(t *testing.T) {
	catalog := productconfig.BuiltInProfileCatalog()
	catalog[productconfig.ProfileCore] = productconfig.ProfileDefinition{}

	if !productconfig.HasCapability(productconfig.ProfileCore, productconfig.CapabilityHost) {
		t.Fatal("mutating cloned catalog must not affect built-in core profile")
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

func TestResolveApplianceProfile_RejectsUnknownProfile(t *testing.T) {
	if _, err := productconfig.ResolveApplianceProfile("unknown", ""); err == nil {
		t.Fatal("expected unknown profile to fail validation")
	}
}

func TestPrepareValuesFile_InjectsApplianceProfile(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("replicaCount: 1\nsecrets:\n  keysSecretName: appliance-keys\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	preparedPath, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, "", workspaceProvisionerImage, builderImage, hostAgentImage, "testapp", productconfig.DefaultLANDNSZone, "")
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

func TestPrepareValuesFile_InjectsApplianceCatalog(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config:\n  applianceProfile: core\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(dir, "appliance-catalog.json")
	catalog := `{
  "version": "appliance.catalog/v1alpha1",
  "profiles": [
    {"name": "custom", "capabilities": ["base", "host"]}
  ],
  "modules": [
    {
      "name": "host-agent",
      "kind": "platform",
      "requiredCapabilities": ["host"],
      "executionMode": "host-agent",
      "entitlementKey": "host-agent",
      "baseURL": "http://host-agent.ace-apps.svc.cluster.local:8080",
      "routes": [
        {"method": "GET", "externalPath": "/api/v1/host/info", "upstreamPath": "/internal/v1/host/info", "permission": "host.read"}
      ],
      "securityClass": "host-privileged"
    }
  ]
}`
	if err := os.WriteFile(catalogPath, []byte(catalog), 0o640); err != nil {
		t.Fatal(err)
	}

	preparedPath, cleanup, err := productconfig.PrepareValuesFile(valuesPath, "custom", catalogPath, "", "", hostAgentImage, "testapp", productconfig.DefaultLANDNSZone, "")
	defer cleanup()
	if err != nil {
		t.Fatalf("PrepareValuesFile returned error: %v", err)
	}
	prepared, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(prepared)
	if !strings.Contains(text, "applianceProfile: custom") || !strings.Contains(text, "applianceCatalog:") || !strings.Contains(text, "name: custom") {
		t.Fatalf("prepared values missing injected appliance catalog: %s", text)
	}
}

func TestPrepareValuesFile_RejectsPlaceholderWorkspaceProvisionerImageDigest(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config:\n  applianceProfile: core\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	_, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, "", "registry.local/workspace-provisioner@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", builderImage, hostAgentImage, "testapp", productconfig.DefaultLANDNSZone, "")
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
	path, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilderLANDNS, "", workspaceProvisionerImage, builderImage, hostAgentImage, "testapp", productconfig.DefaultLANDNSZone, "")
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
