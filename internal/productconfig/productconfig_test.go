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
	if err := os.WriteFile(catalogPath, []byte("workProfiles:\n  - name: builder\nsourceCredentials:\n  - id: git-main\n    gitHost: git.internal.example.com\n    kubernetesSecretName: git-main-key\n    knownHostsSecretName: git-known-hosts\nrepos:\n  - name: app\n    url: git@git.internal.example.com:team/app.git\n    sourceCredentialRef: git-main\n  - name: docs\n    url: https://git.backup.internal.example.com/team/docs.git\nbuildTargets:\n  - name: default\n    repo: app\n    execution: repo_script\n    imageRepository: users/alice/app\n    builderImageDigest: registry.local/buildah@sha256:approved\n"), 0o640); err != nil {
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

func TestPrepareValuesFile_RejectsSSHCatalogRepoWithoutSourceCredentialRef(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("config:\n  applianceProfile: core\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(dir, "build-catalog.yaml")
	if err := os.WriteFile(catalogPath, []byte("sourceCredentials:\n  - id: git-main\n    gitHost: git.internal.example.com\n    kubernetesSecretName: git-main-key\n    knownHostsSecretName: git-known-hosts\nrepos:\n  - name: app\n    url: git@git.internal.example.com:team/app.git\nbuildTargets:\n  - name: default\n    repo: app\n    execution: repo_script\n    imageRepository: users/alice/app\n    builderImageDigest: registry.local/buildah@sha256:approved\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	_, cleanup, err := productconfig.PrepareValuesFile(valuesPath, productconfig.ProfileBuilder, catalogPath)
	defer cleanup()
	if err == nil {
		t.Fatal("expected SSH repo without sourceCredentialRef to be rejected")
	}
	if !strings.Contains(err.Error(), "sourceCredentialRef") {
		t.Fatalf("error = %v, want sourceCredentialRef", err)
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

func TestValidateSourceCredentialProvisioningRequiresManifest(t *testing.T) {
	dir := t.TempDir()
	catalogPath := filepath.Join(dir, "build-catalog.yaml")
	if err := os.WriteFile(catalogPath, []byte("sourceCredentials:\n  - id: git-main\n    gitHost: git.internal.example.com\n    kubernetesSecretName: git-main-key\n    knownHostsSecretName: git-known-hosts\nrepos:\n  - name: app\n    url: git@git.internal.example.com:team/app.git\n    sourceCredentialRef: git-main\nbuildTargets:\n  - name: default\n    repo: app\n    execution: repo_script\n    imageRepository: users/alice/app\n    builderImageDigest: registry.local/buildah@sha256:approved\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	err := productconfig.ValidateSourceCredentialProvisioning(catalogPath, nil)
	if err == nil {
		t.Fatal("expected build catalog source credentials without provisioning manifest to fail")
	}
	if !strings.Contains(err.Error(), "--source-credentials") {
		t.Fatalf("error = %v, want --source-credentials", err)
	}
}

func TestValidateSourceCredentialProvisioningRequiresAllCatalogSecrets(t *testing.T) {
	dir := t.TempDir()
	catalogPath := filepath.Join(dir, "build-catalog.yaml")
	if err := os.WriteFile(catalogPath, []byte("sourceCredentials:\n  - id: git-main\n    gitHost: git.internal.example.com\n    kubernetesSecretName: git-main-key\n    knownHostsSecretName: git-known-hosts\nrepos:\n  - name: app\n    url: git@git.internal.example.com:team/app.git\n    sourceCredentialRef: git-main\nbuildTargets:\n  - name: default\n    repo: app\n    execution: repo_script\n    imageRepository: users/alice/app\n    builderImageDigest: registry.local/buildah@sha256:approved\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	err := productconfig.ValidateSourceCredentialProvisioning(catalogPath, []productconfig.SourceCredentialSecret{{SecretName: "git-main-key"}})
	if err == nil {
		t.Fatal("expected missing known_hosts Secret provisioning to fail")
	}
	if !strings.Contains(err.Error(), "git-known-hosts") {
		t.Fatalf("error = %v, want missing known_hosts Secret name", err)
	}

	err = productconfig.ValidateSourceCredentialProvisioning(catalogPath, []productconfig.SourceCredentialSecret{{SecretName: "git-main-key", KnownHostsSecretName: "git-known-hosts"}})
	if err != nil {
		t.Fatalf("expected complete source credential provisioning to pass: %v", err)
	}
}

func TestLoadSourceCredentialSecrets_ResolvesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte("host key"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "source-credentials.yaml")
	if err := os.WriteFile(path, []byte("credentials:\n  - secretName: git-main-key\n    privateKeyPath: id_ed25519\n    knownHostsSecretName: git-known-hosts\n    knownHostsPath: known_hosts\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	creds, err := productconfig.LoadSourceCredentialSecrets(path, "appliance-builds")
	if err != nil {
		t.Fatalf("LoadSourceCredentialSecrets returned error: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("credentials length = %d, want 1", len(creds))
	}
	if creds[0].Namespace != "appliance-builds" || creds[0].SecretName != "git-main-key" || creds[0].KnownHostsSecretName != "git-known-hosts" {
		t.Fatalf("unexpected credential metadata: %+v", creds[0])
	}
	if creds[0].PrivateKeyPath != filepath.Join(dir, "id_ed25519") || creds[0].KnownHostsPath != filepath.Join(dir, "known_hosts") {
		t.Fatalf("relative paths were not resolved: %+v", creds[0])
	}
}

func TestLoadSourceCredentialSecrets_RejectsInvalidKubernetesNames(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"namespace":        "credentials:\n  - namespace: Zon\n    secretName: git-main-key\n    privateKeyPath: id_ed25519\n",
		"secretName":       "credentials:\n  - secretName: Git_Main_Key\n    privateKeyPath: id_ed25519\n",
		"knownHostsSecret": "credentials:\n  - secretName: git-main-key\n    privateKeyPath: id_ed25519\n    knownHostsSecretName: git_known_hosts\n    knownHostsPath: known_hosts\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".yaml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := productconfig.LoadSourceCredentialSecrets(path, "appliance-builds"); err == nil {
				t.Fatal("expected invalid Kubernetes name to fail")
			}
		})
	}
}
