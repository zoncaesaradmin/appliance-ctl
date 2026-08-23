package productconfig_test

import (
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
)

func TestResolveModulesIncludesHostAgentForHostCapableProfiles(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileCore, productconfig.BuiltInProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	if len(modules) != 2 {
		t.Fatalf("ResolveModulesWithCatalog(core) returned %d modules, want 2", len(modules))
	}
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameHostAgent) {
		t.Fatal("core modules should include host-agent")
	}
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameFiles) {
		t.Fatal("core modules should include files")
	}
	module, _ := productconfig.ModuleNamed(modules, productconfig.ModuleNameHostAgent)
	if module.PrimaryCapability() != productconfig.CapabilityHost {
		t.Fatalf("PrimaryCapability = %q, want %q", module.PrimaryCapability(), productconfig.CapabilityHost)
	}
}

func TestResolveModulesIncludesArtifactAndBuildWhenEnabled(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileBuilder, productconfig.BuiltInProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameArtifactRegistry) {
		t.Fatal("builder modules should include artifact-registry")
	}
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameBuild) {
		t.Fatal("builder modules should include build")
	}
}

func TestResolveModulesIncludesDNSWhenEnabled(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileLANDNS, productconfig.BuiltInProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameLANDNS) {
		t.Fatal("landns modules should include lan-dns")
	}
}

func TestResolveModulesIncludesInferenceWhenEnabled(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileLANLLM, productconfig.BuiltInProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameInferenceRuntime) {
		t.Fatal("lanllm modules should include inference-runtime")
	}
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameFiles) {
		t.Fatal("lanllm modules should include files")
	}
	if productconfig.ModuleEnabled(modules, productconfig.ModuleNameBuild) {
		t.Fatal("lanllm profile should not include build")
	}
}

func TestResolveModulesIncludesVideoWhenEnabled(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileTraining, productconfig.BuiltInProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameVideoRuntime) {
		t.Fatal("training modules should include video-runtime")
	}
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameFiles) {
		t.Fatal("training modules should include files")
	}
	if productconfig.ModuleEnabled(modules, productconfig.ModuleNameBuild) {
		t.Fatal("training profile should not include build")
	}
	if productconfig.ModuleEnabled(modules, productconfig.ModuleNameInferenceRuntime) {
		t.Fatal("training profile should not include inference-runtime")
	}
	module, _ := productconfig.ModuleNamed(modules, productconfig.ModuleNameVideoRuntime)
	if module.PrimaryCapability() != productconfig.CapabilityVideo {
		t.Fatalf("PrimaryCapability = %q, want %q", module.PrimaryCapability(), productconfig.CapabilityVideo)
	}
}

func TestResolveModulesIncludesInferenceForBuilderLANLLM(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileBuilderLANLLM, productconfig.BuiltInProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameInferenceRuntime) {
		t.Fatal("builder-lanllm modules should include inference-runtime")
	}
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameBuild) {
		t.Fatal("builder-lanllm modules should include build")
	}
}

func TestResolveModulesIncludesEverythingForBuilderLANLLMStorageLANDNS(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileBuilderLANLLMStorageLANDNS, productconfig.BuiltInProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
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
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileCore, productconfig.BuiltInProfileCatalog(), denyAllEntitlements{}, productconfig.BuiltInModuleCatalog())
	if len(modules) != 0 {
		t.Fatalf("ResolveModulesWithCatalog(core) with deny-all entitlements returned %d modules, want 0", len(modules))
	}
}

func TestServiceRegistryConfigBuildsHostAgentRoutes(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileCore, productconfig.BuiltInProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	registry := productconfig.ServiceRegistryConfig(modules)
	services, ok := registry["services"].([]map[string]any)
	if !ok {
		t.Fatalf("services = %#v, want []map[string]any", registry["services"])
	}
	if len(services) != 1 {
		t.Fatalf("len(services) = %d, want 1", len(services))
	}
	service := services[0]
	if service["name"] != "host-agent" {
		t.Fatalf("service[name] = %#v, want host-agent", service["name"])
	}
	routes, ok := service["routes"].([]map[string]any)
	if !ok {
		t.Fatalf("routes = %#v, want []map[string]any", service["routes"])
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
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileCore, productconfig.BuiltInProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	if !productconfig.HostAgentEnabled(modules) {
		t.Fatal("HostAgentEnabled(core modules) should be true")
	}
}

type denyAllEntitlements struct{}

func (denyAllEntitlements) IsEntitled(productconfig.ModuleDescriptor, productconfig.EntitlementContext) bool {
	return false
}
