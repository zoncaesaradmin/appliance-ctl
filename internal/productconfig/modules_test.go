package productconfig_test

import (
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
)

func TestResolveModulesIncludesHostAgentForHostCapableProfiles(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileCore, productconfig.BuiltInProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	if len(modules) != 1 {
		t.Fatalf("ResolveModulesWithCatalog(core) returned %d modules, want 1", len(modules))
	}
	module := modules[0]
	if module.Name != "host-agent" {
		t.Fatalf("module.Name = %q, want host-agent", module.Name)
	}
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
	if len(routes) != 7 {
		t.Fatalf("len(routes) = %d, want 7", len(routes))
	}
	pathSet := map[string]bool{}
	for _, route := range routes {
		method, _ := route["method"].(string)
		path, _ := route["externalPath"].(string)
		pathSet[method+" "+path] = true
	}
	for _, want := range []string{
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
