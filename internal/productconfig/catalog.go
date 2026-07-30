package productconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

const CatalogVersionV1Alpha1 = "appliance.catalog/v1alpha1"

type CatalogDocument struct {
	Version  string           `json:"version"`
	Profiles []CatalogProfile `json:"profiles"`
	Modules  []CatalogModule  `json:"modules"`
}

type CatalogProfile struct {
	Name         string       `json:"name"`
	Capabilities []Capability `json:"capabilities"`
}

type CatalogModule struct {
	Name                 string         `json:"name"`
	Kind                 ModuleKind     `json:"kind"`
	RequiredCapabilities []Capability   `json:"requiredCapabilities"`
	Dependencies         []string       `json:"dependencies,omitempty"`
	ExecutionMode        ExecutionMode  `json:"executionMode"`
	EntitlementKey       string         `json:"entitlementKey,omitempty"`
	BaseURL              string         `json:"baseURL,omitempty"`
	Routes               []CatalogRoute `json:"routes,omitempty"`
	SecurityClass        SecurityClass  `json:"securityClass,omitempty"`
}

type CatalogRoute struct {
	Method       string `json:"method"`
	ExternalPath string `json:"externalPath"`
	UpstreamPath string `json:"upstreamPath"`
	Permission   string `json:"permission"`
}

type LoadedCatalog struct {
	Document CatalogDocument
	Profiles ProfileCatalog
	Modules  []ModuleDescriptor
}

func BuiltInCatalogDocument() CatalogDocument {
	document := CatalogDocument{
		Version: CatalogVersionV1Alpha1,
		Modules: make([]CatalogModule, 0, len(BuiltInModuleCatalog())),
	}

	profileNames := make([]string, 0, len(builtInProfileCatalog))
	for profile := range builtInProfileCatalog {
		profileNames = append(profileNames, profile)
	}
	sort.Strings(profileNames)
	document.Profiles = make([]CatalogProfile, 0, len(profileNames))
	for _, name := range profileNames {
		definition := builtInProfileCatalog[name]
		document.Profiles = append(document.Profiles, CatalogProfile{
			Name:         name,
			Capabilities: append([]Capability(nil), definition.Capabilities...),
		})
	}

	for _, module := range BuiltInModuleCatalog() {
		routes := make([]CatalogRoute, 0, len(module.Routes))
		for _, route := range module.Routes {
			routes = append(routes, CatalogRoute{
				Method:       route.Method,
				ExternalPath: route.ExternalPath,
				UpstreamPath: route.UpstreamPath,
				Permission:   route.Permission,
			})
		}
		document.Modules = append(document.Modules, CatalogModule{
			Name:                 module.Name,
			Kind:                 module.Kind,
			RequiredCapabilities: append([]Capability(nil), module.RequiredCapabilities...),
			Dependencies:         append([]string(nil), module.Dependencies...),
			ExecutionMode:        module.ExecutionMode,
			EntitlementKey:       module.EntitlementKey,
			BaseURL:              module.BaseURL,
			Routes:               routes,
			SecurityClass:        module.SecurityClass,
		})
	}

	return document
}

func LoadCatalog(path string) (LoadedCatalog, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return LoadedCatalog{
			Document: BuiltInCatalogDocument(),
			Profiles: BuiltInProfileCatalog(),
			Modules:  BuiltInModuleCatalog(),
		}, nil
	}

	document, err := LoadCatalogDocumentFile(path)
	if err != nil {
		return LoadedCatalog{}, err
	}
	profiles, err := ProfileCatalogFromDocument(document)
	if err != nil {
		return LoadedCatalog{}, err
	}
	modules, err := ModuleCatalogFromDocument(document)
	if err != nil {
		return LoadedCatalog{}, err
	}
	return LoadedCatalog{
		Document: document,
		Profiles: profiles,
		Modules:  modules,
	}, nil
}

func LoadCatalogDocumentFile(path string) (CatalogDocument, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return CatalogDocument{}, fmt.Errorf("catalog path must not be empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return CatalogDocument{}, fmt.Errorf("read catalog %s: %w", path, err)
	}
	var document CatalogDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return CatalogDocument{}, fmt.Errorf("parse catalog %s: %w", path, err)
	}
	if strings.TrimSpace(document.Version) == "" {
		document.Version = CatalogVersionV1Alpha1
	}
	return document, nil
}

func ProfileCatalogFromDocument(document CatalogDocument) (ProfileCatalog, error) {
	profiles := make(ProfileCatalog, len(document.Profiles))
	for idx, profile := range document.Profiles {
		name := strings.TrimSpace(profile.Name)
		if name == "" {
			return nil, fmt.Errorf("catalog profiles[%d].name must not be empty", idx)
		}
		if _, exists := profiles[name]; exists {
			return nil, fmt.Errorf("catalog profiles[%d].name %q is duplicated", idx, name)
		}
		profiles[name] = ProfileDefinition{
			Capabilities: append([]Capability(nil), profile.Capabilities...),
		}
	}
	return profiles, nil
}

func ModuleCatalogFromDocument(document CatalogDocument) ([]ModuleDescriptor, error) {
	modules := make([]ModuleDescriptor, 0, len(document.Modules))
	seen := make(map[string]struct{}, len(document.Modules))
	for idx, module := range document.Modules {
		name := strings.TrimSpace(module.Name)
		if name == "" {
			return nil, fmt.Errorf("catalog modules[%d].name must not be empty", idx)
		}
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("catalog modules[%d].name %q is duplicated", idx, name)
		}
		seen[name] = struct{}{}
		routes := make([]ModuleRoute, 0, len(module.Routes))
		for _, route := range module.Routes {
			routes = append(routes, ModuleRoute{
				Method:       route.Method,
				ExternalPath: route.ExternalPath,
				UpstreamPath: route.UpstreamPath,
				Permission:   route.Permission,
			})
		}
		modules = append(modules, ModuleDescriptor{
			Name:                 name,
			Kind:                 module.Kind,
			RequiredCapabilities: append([]Capability(nil), module.RequiredCapabilities...),
			Dependencies:         append([]string(nil), module.Dependencies...),
			ExecutionMode:        module.ExecutionMode,
			EntitlementKey:       strings.TrimSpace(module.EntitlementKey),
			BaseURL:              strings.TrimSpace(module.BaseURL),
			Routes:               routes,
			SecurityClass:        module.SecurityClass,
		})
	}
	return modules, nil
}
