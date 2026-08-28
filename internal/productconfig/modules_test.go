package productconfig_test

import (
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
)

func TestResolveModulesIncludesHostAgentForHostCapableProfiles(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileStorageLANDNS, testProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameHostAgent) {
		t.Fatal("storage-landns modules should include host-agent")
	}
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameFiles) {
		t.Fatal("storage-landns modules should include files")
	}
	module, _ := productconfig.ModuleNamed(modules, productconfig.ModuleNameHostAgent)
	if module.PrimaryCapability() != productconfig.CapabilityHost {
		t.Fatalf("PrimaryCapability = %q, want %q", module.PrimaryCapability(), productconfig.CapabilityHost)
	}
}

func TestResolveModulesIncludesArtifactAndBuildWhenEnabled(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileBuilder, testProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameArtifactRegistry) {
		t.Fatal("builder modules should include artifact-registry")
	}
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameBuild) {
		t.Fatal("builder modules should include build")
	}
}

func TestResolveModulesIncludesDNSWhenEnabled(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileLANDNS, testProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameLANDNS) {
		t.Fatal("landns modules should include lan-dns")
	}
}

func TestResolveModulesIncludesInferenceWhenEnabled(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileLANLLM, testProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameInferenceRuntime) {
		t.Fatal("lanllm modules should include inference-runtime")
	}
	if productconfig.ModuleEnabled(modules, productconfig.ModuleNameFiles) {
		t.Fatal("lanllm profile should not include files")
	}
	if productconfig.ModuleEnabled(modules, productconfig.ModuleNameBuild) {
		t.Fatal("lanllm profile should not include build")
	}
	if productconfig.ModuleEnabled(modules, productconfig.ModuleNameHostAgent) {
		t.Fatal("lanllm profile should not include host-agent")
	}
}

func TestResolveModulesIncludesInferenceForBuilderLANLLM(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileBuilderLANLLM, testProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameInferenceRuntime) {
		t.Fatal("builder-lanllm modules should include inference-runtime")
	}
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameBuild) {
		t.Fatal("builder-lanllm modules should include build")
	}
}

func TestResolveModulesIncludesEverythingForBuilderLANLLMStorageLANDNS(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileBuilderLANLLMStorageLANDNS, testProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	for _, moduleName := range []string{
		productconfig.ModuleNameHostAgent,
		productconfig.ModuleNameFiles,
		productconfig.ModuleNameArtifactRegistry,
		productconfig.ModuleNameBuild,
		productconfig.ModuleNameLANDNS,
		productconfig.ModuleNameInferenceRuntime,
	} {
		if !productconfig.ModuleEnabled(modules, moduleName) {
			t.Fatalf("builder-lanllm-storage-landns modules should include %s", moduleName)
		}
	}
}

func TestResolveModulesSuppressesModuleWhenNotEntitled(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileCore, testProfileCatalog(), denyAllEntitlements{}, productconfig.BuiltInModuleCatalog())
	if len(modules) != 0 {
		t.Fatalf("ResolveModulesWithCatalog(core) with deny-all entitlements returned %d modules, want 0", len(modules))
	}
}

func TestServiceRegistryConfigBuildsHostAgentRoutes(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileStorageLANDNS, testProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	registry := productconfig.ServiceRegistryConfig(modules)
	services, ok := registry["services"].([]map[string]any)
	if !ok {
		t.Fatalf("services = %#v, want []map[string]any", registry["services"])
	}
	var hostAgent map[string]any
	for _, service := range services {
		if service["name"] == "host-agent" {
			hostAgent = service
			break
		}
	}
	if hostAgent == nil {
		t.Fatal("expected host-agent service in registry")
	}
	routes, ok := hostAgent["routes"].([]map[string]any)
	if !ok {
		t.Fatalf("routes = %#v, want []map[string]any", hostAgent["routes"])
	}
	if len(routes) != 11 {
		t.Fatalf("len(routes) = %d, want 11", len(routes))
	}
	pathSet := map[string]bool{}
	for _, route := range routes {
		method, _ := route["method"].(string)
		path, _ := route["externalPath"].(string)
		pathSet[method+" "+path] = true
	}
	for _, want := range []string{
		"GET /api/v1/host/wifi",
		"PUT /api/v1/host/wifi/enable",
		"PUT /api/v1/host/wifi",
		"GET /api/v1/host/wifi/scan",
		"GET /api/v1/host/wifi-ap",
		"PUT /api/v1/host/wifi-ap",
		"GET /api/v1/host/mdns",
		"PUT /api/v1/host/mdns",
	} {
		if !pathSet[want] {
			t.Fatalf("service routes missing %s", want)
		}
	}
}

func TestHostAgentEnabledReflectsResolvedModules(t *testing.T) {
	if productconfig.HostAgentEnabled(nil) {
		t.Fatal("HostAgentEnabled(nil) should be false")
	}
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileStorageLANDNS, testProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	if !productconfig.HostAgentEnabled(modules) {
		t.Fatal("HostAgentEnabled(storage-landns modules) should be true")
	}
	coreModules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileCore, testProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	if productconfig.HostAgentEnabled(coreModules) {
		t.Fatal("HostAgentEnabled(core modules) should be false")
	}
}

type denyAllEntitlements struct{}

func (denyAllEntitlements) IsEntitled(productconfig.ModuleDescriptor, productconfig.EntitlementContext) bool {
	return false
}
