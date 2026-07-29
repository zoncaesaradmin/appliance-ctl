package productconfig_test

import (
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
)

func TestResolveModulesIncludesHostAgentForHostCapableProfiles(t *testing.T) {
	modules := productconfig.ResolveModules(productconfig.ProfileCore, productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	if len(modules) != 1 {
		t.Fatalf("ResolveModules(core) returned %d modules, want 1", len(modules))
	}
	module := modules[0]
	if module.Name != "host-agent" {
		t.Fatalf("module.Name = %q, want host-agent", module.Name)
	}
	if module.PrimaryCapability() != productconfig.CapabilityHost {
		t.Fatalf("PrimaryCapability = %q, want %q", module.PrimaryCapability(), productconfig.CapabilityHost)
	}
}

func TestResolveModulesSuppressesModuleWhenNotEntitled(t *testing.T) {
	modules := productconfig.ResolveModules(productconfig.ProfileCore, denyAllEntitlements{}, productconfig.BuiltInModuleCatalog())
	if len(modules) != 0 {
		t.Fatalf("ResolveModules(core) with deny-all entitlements returned %d modules, want 0", len(modules))
	}
}

func TestServiceRegistryConfigBuildsHostAgentRoutes(t *testing.T) {
	modules := productconfig.ResolveModules(productconfig.ProfileCore, productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
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
	if len(routes) != 3 {
		t.Fatalf("len(routes) = %d, want 3", len(routes))
	}
}

type denyAllEntitlements struct{}

func (denyAllEntitlements) IsEntitled(productconfig.ModuleDescriptor, productconfig.EntitlementContext) bool {
	return false
}
