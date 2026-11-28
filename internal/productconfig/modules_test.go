package productconfig_test

import (
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
)

func TestGeoDataRoutesRequireCapabilityAndPermissions(t *testing.T) {
	catalog := productconfig.ProfileCatalog{
		"geo":  {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityGeoDataAPI}},
		"core": {Capabilities: []productconfig.Capability{productconfig.CapabilityBase}},
	}
	for _, tc := range []struct {
		profile string
		enabled bool
	}{{"geo", true}, {"core", false}} {
		t.Run(tc.profile, func(t *testing.T) {
			modules := productconfig.ResolveModulesWithCatalog(tc.profile, catalog, productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
			module, ok := productconfig.ModuleNamed(modules, productconfig.ModuleNameGeoDataAPI)
			if ok != tc.enabled {
				t.Fatalf("geo module enabled=%v, want %v", ok, tc.enabled)
			}
			if !ok {
				return
			}
			if len(module.Routes) != 5 {
				t.Fatalf("routes=%d, want 5", len(module.Routes))
			}
			for _, route := range module.Routes {
				want := "geo.write"
				if route.Method == "GET" {
					want = "geo.read"
				}
				if route.Permission != want || route.ExternalPath != "/api/v1/geo/{path...}" || route.UpstreamPath != route.ExternalPath {
					t.Fatalf("unexpected geo route: %+v", route)
				}
			}
		})
	}
}

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

func TestResolveModulesIncludesArtifactWhenEnabled(t *testing.T) {
	modules := productconfig.ResolveModulesWithCatalog(productconfig.ProfileStorage, testProfileCatalog(), productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
	if !productconfig.ModuleEnabled(modules, productconfig.ModuleNameArtifactRegistry) {
		t.Fatal("storage modules should include artifact-registry")
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
	if productconfig.ModuleEnabled(modules, productconfig.ModuleNameHostAgent) {
		t.Fatal("lanllm profile should not include host-agent")
	}
	module, _ := productconfig.ModuleNamed(modules, productconfig.ModuleNameInferenceRuntime)
	if len(module.Routes) != 1 {
		t.Fatalf("inference routes = %#v, want one OpenAI catch-all", module.Routes)
	}
	if module.Routes[0].Method != "ANY" ||
		module.Routes[0].ExternalPath != "/inference/{path...}" ||
		module.Routes[0].StripPrefix != "/inference" ||
		module.Routes[0].UpstreamPath != "" {
		t.Fatalf("inference catch-all = %#v", module.Routes[0])
	}
	registry := productconfig.ServiceRegistryConfig(modules)
	services, _ := registry["services"].([]map[string]any)
	var inference map[string]any
	for _, service := range services {
		if service["name"] == "inference-runtime" {
			inference = service
			break
		}
	}
	if inference == nil {
		t.Fatal("expected inference-runtime in service registry")
	}
	routes, _ := inference["routes"].([]map[string]any)
	if len(routes) != 1 {
		t.Fatalf("service registry routes = %#v, want one catch-all", routes)
	}
	if routes[0]["method"] != "ANY" || routes[0]["externalPath"] != "/inference/{path...}" || routes[0]["stripPrefix"] != "/inference" {
		t.Fatalf("service registry catch-all = %#v", routes[0])
	}
	if _, ok := routes[0]["upstreamPath"]; ok {
		t.Fatalf("catch-all must omit upstreamPath, got %#v", routes[0])
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

func TestInferenceModuleRequiresSharedCapability(t *testing.T) {
	for _, capability := range []productconfig.Capability{"inference", "other"} {
		catalog := productconfig.ProfileCatalog{
			"test-inference": {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, capability}},
		}
		modules := productconfig.ResolveModulesWithCatalog("test-inference", catalog, productconfig.AlwaysEntitled{}, productconfig.BuiltInModuleCatalog())
		got := productconfig.ModuleEnabled(modules, productconfig.ModuleNameInferenceRuntime)
		if got != (capability == productconfig.CapabilityInference) {
			t.Errorf("capability %q enables inference = %v", capability, got)
		}
	}
}
