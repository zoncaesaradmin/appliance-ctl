package productconfig_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
)

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

func TestResolveApplianceProfile_RejectsUnknownProfile(t *testing.T) {
	if _, err := productconfig.ResolveApplianceProfile("unknown", ""); err == nil {
		t.Fatal("expected unknown profile to fail validation")
	}
}

func TestPrepareValuesFile_InjectsApplianceProfile(t *testing.T) {
	valuesPath := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("replicaCount: 1\nsecrets:\n  keysSecretName: appliance-keys\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	preparedPath, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, "")
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

func TestPrepareValuesFile_InjectsBuildCatalog(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config:\n  applianceProfile: core\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(dir, "build-catalog.yaml")
	if err := os.WriteFile(catalogPath, []byte("workProfiles:\n  - name: builder\n    repos:\n      - name: app\n        enabledByDefault: true\n      - name: docs\nrepos:\n  - name: app\n    url: https://git.internal.example.com/team/app.git\n  - name: docs\n    url: https://git.backup.internal.example.com/team/docs.git\nbuildTargets:\n  - name: default\n    repo: app\n    execution: repo_script\n    imageRepository: users/alice/app\n    builderImageDigest: registry.local/buildah@sha256:approved\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	preparedPath, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, catalogPath)
	defer cleanup()
	if err != nil {
		t.Fatalf("PrepareValuesFile returned error: %v", err)
	}
	prepared, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(prepared)
	if !strings.Contains(text, "applianceProfile: builder") || !strings.Contains(text, "buildCatalog:") || !strings.Contains(text, "workProfiles:") {
		t.Fatalf("prepared values missing injected product config: %s", text)
	}
	if !strings.Contains(text, "allowedGitSourceHosts:") || !strings.Contains(text, "- git.internal.example.com") || !strings.Contains(text, "- git.backup.internal.example.com") {
		t.Fatalf("prepared values missing derived Git host allowlist: %s", text)
	}
	if !strings.Contains(text, "allowedBuilderImageDigests:") || !strings.Contains(text, "- registry.local/buildah@sha256:approved") {
		t.Fatalf("prepared values missing derived builder image allowlist: %s", text)
	}
}

func TestPrepareValuesFile_RejectsNonHTTPSCatalogRepo(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config:\n  applianceProfile: core\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(dir, "build-catalog.yaml")
	if err := os.WriteFile(catalogPath, []byte("workProfiles:\n  - name: builder\n    repos:\n      - name: app\nrepos:\n  - name: app\n    url: git@git.internal.example.com:team/app.git\nbuildTargets:\n  - name: default\n    repo: app\n    execution: repo_script\n    imageRepository: users/alice/app\n    builderImageDigest: registry.local/buildah@sha256:approved\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	_, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, catalogPath)
	defer cleanup()
	if err == nil {
		t.Fatal("expected non-HTTPS catalog repo to be rejected")
	}
	if !strings.Contains(err.Error(), "must be an https URL with a host") {
		t.Fatalf("error = %v, want HTTPS validation failure", err)
	}
}

func TestPrepareValuesFile_RejectsEmptyBuildCatalog(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	catalogPath := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(valuesPath, []byte("config: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(catalogPath, []byte("{}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, catalogPath); err == nil {
		t.Fatal("expected empty build catalog to be rejected")
	}
}

func TestPrepareValuesFile_RejectsUnknownWorkspaceProfileRepo(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config:\n  applianceProfile: core\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(dir, "build-catalog.yaml")
	if err := os.WriteFile(catalogPath, []byte("workProfiles:\n  - name: builder\n    repos:\n      - name: missing\nrepos:\n  - name: app\n    url: https://git.internal.example.com/team/app.git\nbuildTargets:\n  - name: default\n    repo: app\n    execution: repo_script\n    imageRepository: users/alice/app\n    builderImageDigest: registry.local/buildah@sha256:approved\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	_, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, catalogPath)
	defer cleanup()
	if err == nil {
		t.Fatal("expected unknown work profile repo membership to be rejected")
	}
	if !strings.Contains(err.Error(), "references unknown repo") {
		t.Fatalf("error = %v, want unknown repo reference", err)
	}
}
