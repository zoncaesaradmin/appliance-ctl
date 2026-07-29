package productconfig

import "strings"

type ModuleKind string

const (
	ModuleKindPlatform    ModuleKind = "platform"
	ModuleKindApplication ModuleKind = "application"
)

type ExecutionMode string

const (
	ExecutionModeClusterService ExecutionMode = "cluster-service"
	ExecutionModeHostAgent      ExecutionMode = "host-agent"
	ExecutionModeWorkflowBacked ExecutionMode = "workflow-backed"
)

type SecurityClass string

const (
	SecurityClassRestricted     SecurityClass = "restricted"
	SecurityClassHostPrivileged SecurityClass = "host-privileged"
	SecurityClassInternalOnly   SecurityClass = "internal-only"
)

type ModuleRoute struct {
	Method       string
	ExternalPath string
	UpstreamPath string
	Permission   string
}

type ModuleDescriptor struct {
	Name                 string
	Kind                 ModuleKind
	RequiredCapabilities []Capability
	Dependencies         []string
	ExecutionMode        ExecutionMode
	EntitlementKey       string
	BaseURL              string
	Routes               []ModuleRoute
	SecurityClass        SecurityClass
}

func (m ModuleDescriptor) PrimaryCapability() Capability {
	if len(m.RequiredCapabilities) == 0 {
		return ""
	}
	return m.RequiredCapabilities[0]
}

type EntitlementContext struct {
	Profile      string
	Capabilities []Capability
}

type EntitlementEvaluator interface {
	IsEntitled(module ModuleDescriptor, ctx EntitlementContext) bool
}

type AlwaysEntitled struct{}

func (AlwaysEntitled) IsEntitled(ModuleDescriptor, EntitlementContext) bool {
	return true
}

func BuiltInModuleCatalog() []ModuleDescriptor {
	return []ModuleDescriptor{
		{
			Name:                 "host-agent",
			Kind:                 ModuleKindPlatform,
			RequiredCapabilities: []Capability{CapabilityHost},
			ExecutionMode:        ExecutionModeHostAgent,
			EntitlementKey:       "host-agent",
			BaseURL:              "http://host-agent.control.svc.cluster.local:8080",
			SecurityClass:        SecurityClassHostPrivileged,
			Routes: []ModuleRoute{
				{Method: "GET", ExternalPath: "/api/v1/host/info", UpstreamPath: "/internal/v1/host/info", Permission: "host.read"},
				{Method: "GET", ExternalPath: "/api/v1/host/stats", UpstreamPath: "/internal/v1/host/stats", Permission: "host.read"},
				{Method: "GET", ExternalPath: "/api/v1/host/health", UpstreamPath: "/internal/v1/host/health", Permission: "host.read"},
			},
		},
	}
}

func ResolveModules(profile string, evaluator EntitlementEvaluator, catalog []ModuleDescriptor) []ModuleDescriptor {
	if evaluator == nil {
		evaluator = AlwaysEntitled{}
	}
	enabled := make([]ModuleDescriptor, 0, len(catalog))
	ctx := EntitlementContext{Profile: profile, Capabilities: profileCapabilities[profile]}
	for _, module := range catalog {
		if !moduleEnabled(profile, module) {
			continue
		}
		if !evaluator.IsEntitled(module, ctx) {
			continue
		}
		enabled = append(enabled, normalizeModule(module))
	}
	return enabled
}

func ServiceRegistryConfig(modules []ModuleDescriptor) map[string]any {
	services := make([]map[string]any, 0, len(modules))
	for _, module := range modules {
		if strings.TrimSpace(module.BaseURL) == "" || len(module.Routes) == 0 {
			continue
		}
		routes := make([]map[string]any, 0, len(module.Routes))
		for _, route := range module.Routes {
			routes = append(routes, map[string]any{
				"method":       strings.ToUpper(strings.TrimSpace(route.Method)),
				"externalPath": strings.TrimSpace(route.ExternalPath),
				"upstreamPath": strings.TrimSpace(route.UpstreamPath),
				"permission":   strings.TrimSpace(route.Permission),
			})
		}
		services = append(services, map[string]any{
			"name":       strings.TrimSpace(module.Name),
			"capability": string(module.PrimaryCapability()),
			"baseURL":    strings.TrimSpace(module.BaseURL),
			"routes":     routes,
		})
	}
	if len(services) == 0 {
		return nil
	}
	return map[string]any{"services": services}
}

func moduleEnabled(profile string, module ModuleDescriptor) bool {
	for _, capability := range module.RequiredCapabilities {
		if !HasCapability(profile, capability) {
			return false
		}
	}
	return true
}

func normalizeModule(module ModuleDescriptor) ModuleDescriptor {
	module.Name = strings.TrimSpace(module.Name)
	module.BaseURL = strings.TrimSpace(module.BaseURL)
	for i := range module.Routes {
		module.Routes[i].Method = strings.ToUpper(strings.TrimSpace(module.Routes[i].Method))
		module.Routes[i].ExternalPath = strings.TrimSpace(module.Routes[i].ExternalPath)
		module.Routes[i].UpstreamPath = strings.TrimSpace(module.Routes[i].UpstreamPath)
		module.Routes[i].Permission = strings.TrimSpace(module.Routes[i].Permission)
	}
	return module
}
