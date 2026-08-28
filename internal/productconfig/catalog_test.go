package productconfig_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
)

func TestLoadCatalogLoadsExplicitCatalogDocument(t *testing.T) {
	document := productconfig.CatalogDocumentFromProfileCatalog(testProfileCatalog())
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	path := filepath.Join(t.TempDir(), "appliance-catalog.json")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	catalog, err := productconfig.LoadCatalog(path)
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	profile, err := productconfig.ResolveApplianceProfileWithCatalog("builder-landns", "", catalog.Profiles)
	if err != nil {
		t.Fatalf("ResolveApplianceProfileWithCatalog(builder-landns): %v", err)
	}
	modules := productconfig.ResolveModulesWithCatalog(profile, catalog.Profiles, productconfig.AlwaysEntitled{}, catalog.Modules)
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
