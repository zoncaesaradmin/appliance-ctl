package productconfig_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
)

const (
	workspaceProvisionerImage = "registry.local/workspace-provisioner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	builderImage              = "registry.local/automation-dev@sha256:5ccdfda08e940614d030e377b75f048a55e3f61cbb0234294ad333f27afe222c"
	zotImage                  = "registry.local/zot@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	fileserverImage           = "registry.local/fileserver@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	corednsImage              = "registry.local/coredns@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func TestPrepareValuesFile_ArtifactCapabilityInjectsRegistryConfig(t *testing.T) {
	valuesPath := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	rendered, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileStorage, "", "", "", "registry1", "appliance.internal", "192.0.2.10", zotImage)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(rendered)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"applianceProfile: storage",
		"canonicalOrigin: https://registry1.appliance.internal",
		"applianceName: registry1",
		"dnsZoneName: appliance.internal",
		"nodeIPv4: 192.0.2.10",
		"zotBaseURL:",
		"kubernetes.io/metadata.name: artifacts",
		"app.kubernetes.io/name: appliance-registry",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered values missing %q:\n%s", want, text)
		}
	}
}

func TestPrepareValuesFile_DNSCapabilityInjectsReadyURL(t *testing.T) {
	valuesPath := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	rendered, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileLANDNS, "", "", "", "dns1", "appliance.internal", "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(rendered)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"applianceProfile: landns",
		"applianceName: dns1",
		"dnsZoneName: appliance.internal",
		"canonicalOrigin: https://dns1.appliance.internal",
		"dnsReadyURL: " + productconfig.DefaultDNSReadyURL,
		"dnsZoneName: " + productconfig.DefaultLANDNSZone,
		"dnsAllowFakeZoneSync: false",
		"kubernetes.io/metadata.name: dns",
		"app.kubernetes.io/name: dns-server",
		"dnsReadyPort: 8181",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered values missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "zotBaseURL:") {
		t.Fatalf("landns must not inject zotBaseURL:\n%s", text)
	}
	for _, forbidden := range []string{
		"dnsBootstrapHostname: appliance",
		"dnsBootstrapIPv4: 192.0.2.10",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("landns must not seed DNS A records from public_host (%q present):\n%s", forbidden, text)
		}
	}
}

func TestPrepareDNSValuesFile_DigestPinAndLocalZone(t *testing.T) {
	path, cleanup, err := productconfig.PrepareDNSValuesFile(t.TempDir(), corednsImage, "appliance.internal", "192.0.2.10", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"digest: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		"hostNetwork: true",
		"hostname: \"\"",
		"ipv4: 192.0.2.10",
		"name: appliance.internal",
		"hostPath: /data/zon/logs/dns",
		"- 1.1.1.1",
		"create: false",
		"name: dns",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered dns values missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "hostname: appliance") {
		t.Fatalf("dns values must not seed a product hostname:\n%s", text)
	}
}

func TestPrepareRegistryValuesFile_DigestPinAndPersistence(t *testing.T) {
	path, cleanup, err := productconfig.PrepareRegistryValuesFile(t.TempDir(), zotImage, fileserverImage, "registry1.appliance.internal")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") ||
		!strings.Contains(text, "digest: sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd") ||
		!strings.Contains(text, "repository: registry.local/fileserver") ||
		!strings.Contains(text, "hostPath: /data/zon/files") ||
		!strings.Contains(text, "accessMode: ReadWriteOnce") ||
		!strings.Contains(text, productconfig.DefaultRegistryPublicKeySecret) ||
		!strings.Contains(text, "kubernetes.io/metadata.name: control") ||
		!strings.Contains(text, "app.kubernetes.io/name: api-server") ||
		!strings.Contains(text, "hostPath: /data/zon/logs/artifactserver") ||
		!strings.Contains(text, "hostPath: /data/zon/logs/fileserver") {
		t.Fatalf("unexpected registry values:\n%s", text)
	}
}
func TestPrepareRegistryValuesFile_UsesApplianceFQDN(t *testing.T) {
	path, cleanup, err := productconfig.PrepareRegistryValuesFile(t.TempDir(), zotImage, fileserverImage, "registry1.appliance.internal")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "realm: https://registry1.appliance.internal/api/v1/registry/token") {
		t.Fatalf("rendered registry values missing realm override:\n%s", text)
	}
	if strings.Contains(text, "host: appliance.internal.example.com") {
		t.Fatalf("registry ingress host should remain empty by default so /v2 matches appliance IP access too:\n%s", text)
	}
}

func TestResolveApplianceIdentity(t *testing.T) {
	identity, err := productconfig.ResolveApplianceIdentity("Registry1", "")
	if err != nil {
		t.Fatalf("ResolveApplianceIdentity: %v", err)
	}
	if identity.Name != "registry1" || identity.Zone != productconfig.DefaultLANDNSZone || identity.FQDN != "registry1.appliance.internal" {
		t.Fatalf("identity = %+v", identity)
	}
	if _, err := productconfig.ResolveApplianceIdentity("bad.name", "appliance.internal"); err == nil {
		t.Fatal("expected multi-label appliance name to fail")
	}
	if _, err := productconfig.ResolveApplianceIdentity("dns1", "appliance.local"); err == nil {
		t.Fatal("expected .local zone to fail")
	}
}

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

func TestResolveApplianceProfile_AcceptsLANDNSProfiles(t *testing.T) {
	for _, requested := range []string{"landns", "storage-landns", "builder-landns", "builder-storage-landns"} {
		t.Run(requested, func(t *testing.T) {
			profile, err := productconfig.ResolveApplianceProfile(requested, "")
			if err != nil {
				t.Fatalf("ResolveApplianceProfile(%q) returned error: %v", requested, err)
			}
			if profile != requested {
				t.Fatalf("profile = %q, want %q", profile, requested)
			}
			wantDNS := true
			if productconfig.HasCapability(profile, productconfig.CapabilityDNS) != wantDNS {
				t.Fatalf("HasCapability(dns) = %v, want %v", !wantDNS, wantDNS)
			}
		})
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

	preparedPath, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, "", workspaceProvisionerImage, builderImage, "testapp", productconfig.DefaultLANDNSZone, "")
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
	if err := os.WriteFile(catalogPath, []byte("workProfiles:\n  - name: builder\n    repos:\n      - name: app\n        enabledByDefault: true\n      - name: docs\nrepos:\n  - name: app\n    url: https://git.internal.example.com/team/app.git\n  - name: docs\n    url: https://git.backup.internal.example.com/team/docs.git\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	preparedPath, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, catalogPath, workspaceProvisionerImage, builderImage, "testapp", productconfig.DefaultLANDNSZone, "")
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
	if strings.Contains(text, "allowedBuilderImageDigests:") {
		t.Fatalf("prepared values should not derive builder image allowlist from workspace-only catalog: %s", text)
	}
	if !strings.Contains(text, "workspaceProvisionerImageDigest: registry.local/workspace-provisioner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatalf("prepared values missing workspace provisioner image: %s", text)
	}
}

func TestPrepareValuesFile_InjectsNestedBuildTargets(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config:\n  applianceProfile: core\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(dir, "build-catalog.yaml")
	catalog := `workProfiles:
  - name: builder
    repos:
      - name: app
repos:
  - name: app
    url: https://git.internal.example.com/team/app.git
    defaultRef: main
    buildTargets:
      - name: app
        execution: make
        args: [build]
        imageRepository: users/example/app
      - name: app-api
        execution: make
        args: [api]
        imageRepository: users/example/app-api
`
	if err := os.WriteFile(catalogPath, []byte(catalog), 0o640); err != nil {
		t.Fatal(err)
	}

	preparedPath, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, catalogPath, workspaceProvisionerImage, builderImage, "testapp", productconfig.DefaultLANDNSZone, "")
	defer cleanup()
	if err != nil {
		t.Fatalf("PrepareValuesFile returned error: %v", err)
	}
	prepared, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(prepared)
	if !strings.Contains(text, "buildTargets:") || !strings.Contains(text, "name: app-api") || !strings.Contains(text, "repo: app") {
		t.Fatalf("prepared values missing flattened nested build targets: %s", text)
	}
	if strings.Count(text, "buildTargets:") != 1 {
		t.Fatalf("prepared values should contain exactly one top-level buildTargets list: %s", text)
	}
}

func TestPrepareValuesFile_InjectsBuildTargets(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config:\n  applianceProfile: core\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(dir, "build-catalog.yaml")
	catalog := `workProfiles:
  - name: builder
    repos:
      - name: app
repos:
  - name: app
    url: https://git.internal.example.com/team/app.git
buildTargets:
  - name: app
    repo: app
    execution: make
    args: [build]
    imageRepository: users/example/app
  - name: app-api
    repo: app
    execution: make
    args: [api]
    imageRepository: users/example/app-api
`
	if err := os.WriteFile(catalogPath, []byte(catalog), 0o640); err != nil {
		t.Fatal(err)
	}

	preparedPath, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, catalogPath, workspaceProvisionerImage, builderImage, "testapp", productconfig.DefaultLANDNSZone, "")
	defer cleanup()
	if err != nil {
		t.Fatalf("PrepareValuesFile returned error: %v", err)
	}
	prepared, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(prepared)
	if !strings.Contains(text, "buildTargets:") || !strings.Contains(text, "- build") || !strings.Contains(text, "name: app-api") {
		t.Fatalf("prepared values missing injected build targets: %s", text)
	}
	if strings.Contains(text, "allowedBuilderImageDigests:") {
		t.Fatalf("prepared values should not derive builder image allowlist from catalog: %s", text)
	}
	if !strings.Contains(text, "builderImageDigest: registry.local/automation-dev@sha256:5ccdfda08e940614d030e377b75f048a55e3f61cbb0234294ad333f27afe222c") {
		t.Fatalf("prepared values missing bundled builder image: %s", text)
	}
}

func TestPrepareValuesFile_RejectsInvalidBuildTarget(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config:\n  applianceProfile: core\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(dir, "build-catalog.yaml")
	if err := os.WriteFile(catalogPath, []byte("workProfiles:\n  - name: builder\n    repos:\n      - name: app\nrepos:\n  - name: app\n    url: https://git.internal.example.com/team/app.git\nbuildTargets:\n  - name: app\n    repo: app\n    execution: make\n    imageRepository: users/example/app\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	_, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, catalogPath, workspaceProvisionerImage, builderImage, "testapp", productconfig.DefaultLANDNSZone, "")
	defer cleanup()
	if err == nil {
		t.Fatal("expected build target missing args to be rejected")
	}
	if !strings.Contains(err.Error(), "args must contain exactly one make target") {
		t.Fatalf("error = %v, want makeTarget validation failure", err)
	}
}

func TestPrepareValuesFile_RejectsUnknownBuildTargetRepo(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config:\n  applianceProfile: core\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(dir, "build-catalog.yaml")
	if err := os.WriteFile(catalogPath, []byte("workProfiles:\n  - name: builder\n    repos:\n      - name: app\nrepos:\n  - name: app\n    url: https://git.internal.example.com/team/app.git\nbuildTargets:\n  - name: other\n    repo: missing\n    execution: make\n    args: [build]\n    imageRepository: users/example/other\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	_, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, catalogPath, workspaceProvisionerImage, builderImage, "testapp", productconfig.DefaultLANDNSZone, "")
	defer cleanup()
	if err == nil {
		t.Fatal("expected unknown build target repo to be rejected")
	}
	if !strings.Contains(err.Error(), "references unknown repo") {
		t.Fatalf("error = %v, want unknown repo reference", err)
	}
}

func TestPrepareValuesFile_RejectsDuplicateBuildTargetAlias(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config:\n  applianceProfile: core\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(dir, "build-catalog.yaml")
	catalog := `workProfiles:
  - name: builder
    repos:
      - name: app
repos:
  - name: app
    url: https://git.internal.example.com/team/app.git
buildTargets:
  - name: app
    repo: app
    execution: make
    args: [build]
    imageRepository: users/example/app
  - name: app-api
    aliases: [app]
    repo: app
    execution: make
    args: [api]
    imageRepository: users/example/app-api
`
	if err := os.WriteFile(catalogPath, []byte(catalog), 0o640); err != nil {
		t.Fatal(err)
	}

	_, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, catalogPath, workspaceProvisionerImage, builderImage, "testapp", productconfig.DefaultLANDNSZone, "")
	defer cleanup()
	if err == nil {
		t.Fatal("expected duplicate build target alias to be rejected")
	}
	if !strings.Contains(err.Error(), "duplicates build target name/alias") {
		t.Fatalf("error = %v, want duplicate alias validation failure", err)
	}
}

func TestPrepareValuesFile_RejectsNonHTTPSCatalogRepo(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config:\n  applianceProfile: core\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(dir, "build-catalog.yaml")
	if err := os.WriteFile(catalogPath, []byte("workProfiles:\n  - name: builder\n    repos:\n      - name: app\nrepos:\n  - name: app\n    url: git@git.internal.example.com:team/app.git\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	_, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, catalogPath, workspaceProvisionerImage, builderImage, "testapp", productconfig.DefaultLANDNSZone, "")
	defer cleanup()
	if err == nil {
		t.Fatal("expected non-HTTPS catalog repo to be rejected")
	}
	if !strings.Contains(err.Error(), "must be an https URL with a host") {
		t.Fatalf("error = %v, want HTTPS validation failure", err)
	}
}

func TestPrepareValuesFile_RejectsPlaceholderWorkspaceProvisionerImageDigest(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config:\n  applianceProfile: core\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(dir, "build-catalog.yaml")
	if err := os.WriteFile(catalogPath, []byte("workProfiles:\n  - name: builder\n    repos:\n      - name: app\nrepos:\n  - name: app\n    url: https://git.internal.example.com/team/app.git\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	_, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, catalogPath, "registry.local/workspace-provisioner@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", builderImage, "testapp", productconfig.DefaultLANDNSZone, "")
	defer cleanup()
	if err == nil {
		t.Fatal("expected placeholder workspace provisioner image digest to be rejected")
	}
	if !strings.Contains(err.Error(), "workspace provisioner image") {
		t.Fatalf("error = %v, want placeholder digest validation failure", err)
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
	if _, _, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, catalogPath, workspaceProvisionerImage, builderImage, "testapp", productconfig.DefaultLANDNSZone, ""); err == nil {
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
	if err := os.WriteFile(catalogPath, []byte("workProfiles:\n  - name: builder\n    repos:\n      - name: missing\nrepos:\n  - name: app\n    url: https://git.internal.example.com/team/app.git\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	_, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, catalogPath, workspaceProvisionerImage, builderImage, "testapp", productconfig.DefaultLANDNSZone, "")
	defer cleanup()
	if err == nil {
		t.Fatal("expected unknown work profile repo membership to be rejected")
	}
	if !strings.Contains(err.Error(), "references unknown repo") {
		t.Fatalf("error = %v, want unknown repo reference", err)
	}
}
