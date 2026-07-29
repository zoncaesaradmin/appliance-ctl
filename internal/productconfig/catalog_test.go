package productconfig_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
)

func TestFileCatalogLoaderLoadsBuiltInCatalogDocument(t *testing.T) {
	document := productconfig.BuiltInCatalogDocument()
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	path := filepath.Join(t.TempDir(), "appliance-catalog.json")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	loader := productconfig.FileCatalogLoader{Path: path}
	profile, err := productconfig.ResolveApplianceProfileWithLoader("builder-landns", "", loader)
	if err != nil {
		t.Fatalf("ResolveApplianceProfileWithLoader(builder-landns): %v", err)
	}
	modules, err := productconfig.ResolveModulesWithLoaders(profile, loader, loader, productconfig.AlwaysEntitled{})
	if err != nil {
		t.Fatalf("ResolveModulesWithLoaders: %v", err)
	}
	for _, moduleName := range []string{
		productconfig.ModuleNameHostAgent,
		productconfig.ModuleNameArtifactRegistry,
		productconfig.ModuleNameBuild,
		productconfig.ModuleNameLANDNS,
	} {
		if !productconfig.ModuleEnabled(modules, moduleName) {
			t.Fatalf("expected module %q to be enabled", moduleName)
		}
	}
}
