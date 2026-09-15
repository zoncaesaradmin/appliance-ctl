package releasebundle

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/zoncaesaradmin/appliance-ctl/internal/metadatabundle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/runtimeconfig"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/bundle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/releaseinput"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

type HostBaseline struct {
	OS        string `json:"os"`
	OSVersion string `json:"osVersion"`
	Arch      string `json:"arch"`
}

type EntryConfig struct {
	SourcePath     string `json:"sourcePath"`
	TargetPath     string `json:"targetPath"`
	Component      string `json:"component"`
	Executable     bool   `json:"executable,omitempty"`
	ImageReference string `json:"imageReference,omitempty"`
}

const (
	PackFoundation  = "foundation"
	PackDevPlatform = "dev-platform"
	PackDeviceUser  = "deviceuser"
	PackStdLLMAMD64 = "std-llm-amd64"
	PackAccLLMAMD64 = "acc-llm-amd64"
	PackAccLLMARM64 = "acc-llm-arm64"
)

type Config struct {
	SchemaVersion         int           `json:"schemaVersion"`
	BundleVersion         string        `json:"bundleVersion"`
	ReleaseInputDir       string        `json:"releaseInputDir"`
	BundleDir             string        `json:"bundleDir"`
	SigningKeyID          string        `json:"signingKeyId"`
	SigningPrivateKeyPath string        `json:"signingPrivateKeyPath"`
	HostBaseline          HostBaseline  `json:"hostBaseline"`
	Entries               []EntryConfig `json:"entries"`
	// Pack selects which signed deliverable to assemble.
	// Empty means legacy full bundle (everything). PackFoundation excludes
	// dev-platform, deviceuser, and the selected inference package artifacts.
	Pack string `json:"pack,omitempty"`
}

type Result struct {
	BundleDir     string
	BundleVersion string
	ReleaseID     string
	ManifestPath  string
	SignaturePath string
	PublicKeyPath string
	EntryCount    int
}

type manifestEntry struct {
	Path           string `json:"path"`
	Component      string `json:"component"`
	Digest         string `json:"digest"`
	SizeBytes      int64  `json:"sizeBytes"`
	Executable     bool   `json:"executable,omitempty"`
	ImageReference string `json:"imageReference,omitempty"`
}

type manifestDoc struct {
	Runtimes      map[string]runtimeconfig.Selection `json:"runtimes,omitempty"`
	SchemaVersion int                                `json:"schemaVersion"`
	BundleVersion string                             `json:"bundleVersion"`
	ReleaseID     string                             `json:"releaseId"`
	HostBaseline  HostBaseline                       `json:"hostBaseline"`
	BuiltAt       string                             `json:"builtAt"`
	Compatibility any                                `json:"compatibility"`
	SigningKeyID  string                             `json:"signingKeyId"`
	Entries       []manifestEntry                    `json:"entries"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("releasebundle: read config %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("releasebundle: parse config %s: %w", path, err)
	}
	if cfg.SchemaVersion != 1 {
		return Config{}, fmt.Errorf("releasebundle: config schemaVersion must be 1")
	}
	if cfg.BundleVersion == "" || cfg.ReleaseInputDir == "" || cfg.BundleDir == "" || cfg.SigningKeyID == "" || cfg.SigningPrivateKeyPath == "" {
		return Config{}, fmt.Errorf("releasebundle: bundleVersion, releaseInputDir, bundleDir, signingKeyId, and signingPrivateKeyPath are required")
	}
	if cfg.HostBaseline.OS == "" || cfg.HostBaseline.OSVersion == "" || cfg.HostBaseline.Arch == "" {
		return Config{}, fmt.Errorf("releasebundle: hostBaseline.os, hostBaseline.osVersion, and hostBaseline.arch are required")
	}
	switch cfg.Pack {
	case "", PackFoundation, PackDevPlatform, PackDeviceUser, PackStdLLMAMD64, PackAccLLMAMD64, PackAccLLMARM64:
	default:
		return Config{}, fmt.Errorf("releasebundle: pack must be empty, %q, %q, %q, %q, %q, or %q", PackFoundation, PackDevPlatform, PackDeviceUser, PackStdLLMAMD64, PackAccLLMAMD64, PackAccLLMARM64)
	}
	if len(cfg.Entries) == 0 {
		return Config{}, fmt.Errorf("releasebundle: at least one entry is required")
	}
	return cfg, nil
}

func Assemble(ctx context.Context, cfg Config) (Result, error) {
	_ = ctx
	input, _, err := releaseinput.Load(cfg.ReleaseInputDir)
	if err != nil {
		return Result{}, err
	}
	if err := prepareBundleDir(cfg.BundleDir); err != nil {
		return Result{}, err
	}

	priv, err := verify.LoadPrivateKey(cfg.SigningPrivateKeyPath)
	if err != nil {
		return Result{}, err
	}

	entryByTarget := map[string]EntryConfig{}
	for _, entry := range cfg.Entries {
		if err := validateConfiguredEntry(entry); err != nil {
			return Result{}, err
		}
		target := filepath.ToSlash(strings.TrimPrefix(entry.TargetPath, "/"))
		if _, exists := entryByTarget[target]; exists {
			return Result{}, fmt.Errorf("releasebundle: duplicate targetPath %q", target)
		}
		entry.TargetPath = target
		if !entryBelongsToPack(entry, cfg.Pack) {
			continue
		}
		entryByTarget[target] = entry
	}

	includeProductAutoAdds := cfg.Pack == "" || cfg.Pack == PackFoundation
	includeFoundationMDNSAutoAdds := cfg.Pack == "" || cfg.Pack == PackFoundation
	includeDevPlatformAutoAdds := cfg.Pack == "" || cfg.Pack == PackDevPlatform
	includeDeviceUserAutoAdds := cfg.Pack == "" || cfg.Pack == PackDeviceUser
	includeInferenceAutoAdd := cfg.Pack == "" || cfg.Pack == PackStdLLMAMD64 || cfg.Pack == PackAccLLMAMD64 || cfg.Pack == PackAccLLMARM64
	includeEvidenceDirs := cfg.Pack == "" || cfg.Pack == PackFoundation
	if cfg.Pack == PackStdLLMAMD64 || cfg.Pack == PackAccLLMAMD64 || cfg.Pack == PackAccLLMARM64 {
		// Inference packs are auto-add only; drop any leftover cfg entries.
		entryByTarget = map[string]EntryConfig{}
	}

	if includeProductAutoAdds {
		// Carry the product configuration schema and evidence directories into the final bundle.
		uiImageTarget := "oci-images/" + filepath.Base(input.Artifacts.UIImage.Path)
		if _, exists := entryByTarget[uiImageTarget]; !exists {
			entryByTarget[uiImageTarget] = EntryConfig{
				SourcePath:     input.Artifacts.UIImage.Path,
				TargetPath:     uiImageTarget,
				Component:      "oci-images",
				ImageReference: input.Artifacts.UIImage.ImageReference,
			}
		}
	}

	if includeFoundationMDNSAutoAdds {
		// The host-side daemon and its offline packages provide the appliance
		// baseline mDNS responder. They do not grant the host capability.
		hostAgentBinaryTarget := "bin/" + filepath.Base(input.Artifacts.HostAgentBinary.Path)
		if _, exists := entryByTarget[hostAgentBinaryTarget]; !exists {
			entryByTarget[hostAgentBinaryTarget] = EntryConfig{
				SourcePath: input.Artifacts.HostAgentBinary.Path,
				TargetPath: hostAgentBinaryTarget,
				Component:  "appliance",
				Executable: true,
			}
		}
	}

	if includeDeviceUserAutoAdds {
		if strings.TrimSpace(input.Artifacts.HostAgentImage.Path) == "" {
			return Result{}, fmt.Errorf("releasebundle: deviceuser pack requires hostAgentImage in release-input")
		}
		hostAgentImageTarget := "oci-images/" + filepath.Base(input.Artifacts.HostAgentImage.Path)
		if _, exists := entryByTarget[hostAgentImageTarget]; !exists {
			if !isCanonicalHostAgentReference(input.Artifacts.HostAgentImage.ImageReference) {
				return Result{}, fmt.Errorf("releasebundle: host-agent imageReference must be registry.local/appliance-host-agent@sha256:<64 lowercase hex>, got %q", input.Artifacts.HostAgentImage.ImageReference)
			}
			entryByTarget[hostAgentImageTarget] = EntryConfig{
				SourcePath:     input.Artifacts.HostAgentImage.Path,
				TargetPath:     hostAgentImageTarget,
				Component:      "oci-images",
				ImageReference: input.Artifacts.HostAgentImage.ImageReference,
			}
		}
	}

	if includeDevPlatformAutoAdds {
		if strings.TrimSpace(input.Artifacts.ArtifactServerImage.Path) == "" || strings.TrimSpace(input.Artifacts.ArtifactServerChart.Path) == "" {
			return Result{}, fmt.Errorf("releasebundle: dev-platform pack requires artifactServerImage and artifactServerChart in release-input")
		}
		if strings.TrimSpace(input.Artifacts.DnsImage.Path) == "" || strings.TrimSpace(input.Artifacts.DnsChart.Path) == "" {
			return Result{}, fmt.Errorf("releasebundle: dev-platform pack requires dnsImage and dnsChart in release-input")
		}
		artifactServerImageTarget := "oci-images/" + filepath.Base(input.Artifacts.ArtifactServerImage.Path)
		if _, exists := entryByTarget[artifactServerImageTarget]; !exists {
			if !isCanonicalArtifactServerReference(input.Artifacts.ArtifactServerImage.ImageReference) {
				return Result{}, fmt.Errorf("releasebundle: artifact server imageReference must be registry.local/artifact-server@sha256:<64 lowercase hex>, got %q", input.Artifacts.ArtifactServerImage.ImageReference)
			}
			entryByTarget[artifactServerImageTarget] = EntryConfig{
				SourcePath:     input.Artifacts.ArtifactServerImage.Path,
				TargetPath:     artifactServerImageTarget,
				Component:      "oci-images",
				ImageReference: input.Artifacts.ArtifactServerImage.ImageReference,
			}
		}
		artifactServerChartBase := filepath.Base(input.Artifacts.ArtifactServerChart.Path)
		if !strings.HasPrefix(strings.ToLower(artifactServerChartBase), "appliance-registry-") {
			artifactServerChartBase = "appliance-registry-" + artifactServerChartBase
		}
		artifactServerChartTarget := "chart/" + artifactServerChartBase
		if _, exists := entryByTarget[artifactServerChartTarget]; !exists {
			entryByTarget[artifactServerChartTarget] = EntryConfig{
				SourcePath: input.Artifacts.ArtifactServerChart.Path,
				TargetPath: artifactServerChartTarget,
				Component:  "chart",
			}
		}
		dnsImageTarget := "oci-images/" + filepath.Base(input.Artifacts.DnsImage.Path)
		if _, exists := entryByTarget[dnsImageTarget]; !exists {
			if !isCanonicalDNSReference(input.Artifacts.DnsImage.ImageReference) {
				return Result{}, fmt.Errorf("releasebundle: coredns imageReference must be registry.local/coredns@sha256:<64 lowercase hex>, got %q", input.Artifacts.DnsImage.ImageReference)
			}
			entryByTarget[dnsImageTarget] = EntryConfig{
				SourcePath:     input.Artifacts.DnsImage.Path,
				TargetPath:     dnsImageTarget,
				Component:      "oci-images",
				ImageReference: input.Artifacts.DnsImage.ImageReference,
			}
		}
		dnsChartBase := filepath.Base(input.Artifacts.DnsChart.Path)
		if !strings.HasPrefix(strings.ToLower(dnsChartBase), "appliance-dns-") {
			dnsChartBase = "appliance-dns-" + dnsChartBase
		}
		dnsChartTarget := "chart/" + dnsChartBase
		if _, exists := entryByTarget[dnsChartTarget]; !exists {
			entryByTarget[dnsChartTarget] = EntryConfig{
				SourcePath: input.Artifacts.DnsChart.Path,
				TargetPath: dnsChartTarget,
				Component:  "chart",
			}
		}
	}

	if includeProductAutoAdds {
		if input.Artifacts.MessageBrokerImage.Path != "" && input.Artifacts.MessageBrokerChart.Path != "" {
			messageBrokerImageTarget := "oci-images/" + filepath.Base(input.Artifacts.MessageBrokerImage.Path)
			if _, exists := entryByTarget[messageBrokerImageTarget]; !exists {
				if !isCanonicalMessageBrokerReference(input.Artifacts.MessageBrokerImage.ImageReference) {
					return Result{}, fmt.Errorf("releasebundle: message broker imageReference must be registry.local/nats@sha256:<64 lowercase hex>, got %q", input.Artifacts.MessageBrokerImage.ImageReference)
				}
				entryByTarget[messageBrokerImageTarget] = EntryConfig{SourcePath: input.Artifacts.MessageBrokerImage.Path, TargetPath: messageBrokerImageTarget, Component: "oci-images", ImageReference: input.Artifacts.MessageBrokerImage.ImageReference}
			}
			messageBrokerChartTarget := "chart/" + filepath.Base(input.Artifacts.MessageBrokerChart.Path)
			if _, exists := entryByTarget[messageBrokerChartTarget]; !exists {
				entryByTarget[messageBrokerChartTarget] = EntryConfig{SourcePath: input.Artifacts.MessageBrokerChart.Path, TargetPath: messageBrokerChartTarget, Component: "chart"}
			}
		}
		metadataBundleBase := filepath.Base(input.Artifacts.MetadataBundle.Path)
		metadataBundleTarget := "artifacts/" + metadataBundleBase
		if _, exists := entryByTarget[metadataBundleTarget]; !exists {
			entryByTarget[metadataBundleTarget] = EntryConfig{
				SourcePath: input.Artifacts.MetadataBundle.Path,
				TargetPath: metadataBundleTarget,
				Component:  "artifacts",
			}
		}

		configSchemaTarget := "configuration/configuration.schema.json"
		if _, exists := entryByTarget[configSchemaTarget]; !exists {
			entryByTarget[configSchemaTarget] = EntryConfig{
				SourcePath: input.Artifacts.ConfigurationSchema.Path,
				TargetPath: configSchemaTarget,
				Component:  "configuration",
			}
		}
	}

	runtimes := map[string]runtimeconfig.Selection{}
	if includeInferenceAutoAdd {
		if input.Artifacts.InferenceRuntimeImage.Path == "" || input.Artifacts.InferenceChart.Path == "" {
			if cfg.Pack == PackStdLLMAMD64 || cfg.Pack == PackAccLLMAMD64 || cfg.Pack == PackAccLLMARM64 {
				return Result{}, fmt.Errorf("releasebundle: %s pack requires release-input inferenceRuntimeImage and inferenceChart", cfg.Pack)
			}
		} else {
			packages, err := metadatabundle.LoadPackageCatalogArchive(input.Artifacts.MetadataBundle.Path)
			if err != nil {
				return Result{}, fmt.Errorf("releasebundle: runtime package metadata: %w", err)
			}
			// The legacy single-bundle form has no pack ID. It represents the
			// standard CPU delivery, so retain that explicit selection rather
			// than asking the complete catalog to choose between architecture
			// variants. Split inference packs use their own pack ID directly.
			inferencePackage := cfg.Pack
			if inferencePackage == "" {
				inferencePackage = PackStdLLMAMD64
			}
			selected, err := metadatabundle.ResolvePackage(packages, "inference", inferencePackage)
			if err != nil {
				return Result{}, err
			}
			if err := runtimeconfig.ValidateInference(selected); err != nil {
				return Result{}, err
			}
			runtimes["inference"] = selected
			inferenceImageTarget := "oci-images/" + filepath.Base(input.Artifacts.InferenceRuntimeImage.Path)
			if _, exists := entryByTarget[inferenceImageTarget]; !exists {
				if !isCanonicalInferenceRuntimeReference(input.Artifacts.InferenceRuntimeImage.ImageReference) {
					return Result{}, fmt.Errorf("releasebundle: inference-runtime imageReference must be registry.local/inference-runtime@sha256:<64 lowercase hex>, got %q", input.Artifacts.InferenceRuntimeImage.ImageReference)
				}
				entryByTarget[inferenceImageTarget] = EntryConfig{
					SourcePath:     input.Artifacts.InferenceRuntimeImage.Path,
					TargetPath:     inferenceImageTarget,
					Component:      "oci-images",
					ImageReference: input.Artifacts.InferenceRuntimeImage.ImageReference,
				}
			}
			inferenceChartBase := filepath.Base(input.Artifacts.InferenceChart.Path)
			if !strings.HasPrefix(strings.ToLower(inferenceChartBase), "appliance-inference-") {
				inferenceChartBase = "appliance-inference-" + inferenceChartBase
			}
			inferenceChartTarget := "chart/" + inferenceChartBase
			if _, exists := entryByTarget[inferenceChartTarget]; !exists {
				entryByTarget[inferenceChartTarget] = EntryConfig{
					SourcePath: input.Artifacts.InferenceChart.Path,
					TargetPath: inferenceChartTarget,
					Component:  "chart",
				}
			}
		}
	}

	publicKeyTarget := "public-keys/release-signing.pub"
	publicKeyBytes, err := encodePublicKeyPEM(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(filepath.Join(cfg.BundleDir, filepath.Dir(publicKeyTarget)), 0o750); err != nil {
		return Result{}, fmt.Errorf("releasebundle: create public-key dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(cfg.BundleDir, publicKeyTarget), publicKeyBytes, 0o644); err != nil {
		return Result{}, fmt.Errorf("releasebundle: write %s: %w", publicKeyTarget, err)
	}

	var manifestEntries []manifestEntry
	targets := make([]string, 0, len(entryByTarget))
	for target := range entryByTarget {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	for _, target := range targets {
		entry := entryByTarget[target]
		manifestEntry, err := copyEntry(cfg.BundleDir, entry)
		if err != nil {
			return Result{}, err
		}
		manifestEntries = append(manifestEntries, manifestEntry)
	}

	if includeEvidenceDirs {
		if err := addDirectoryEntries(cfg.BundleDir, input.Artifacts.SBOM.Path, "sbom", &manifestEntries); err != nil {
			return Result{}, err
		}
		if err := addDirectoryEntries(cfg.BundleDir, input.Artifacts.Provenance.Path, "provenance", &manifestEntries); err != nil {
			return Result{}, err
		}
		if err := addDirectoryEntries(cfg.BundleDir, input.Artifacts.Notices.Path, "notices", &manifestEntries); err != nil {
			return Result{}, err
		}
		if err := addDirectoryEntries(cfg.BundleDir, input.Artifacts.Tests.Path, "tests", &manifestEntries); err != nil {
			return Result{}, err
		}
	}
	if includeFoundationMDNSAutoAdds {
		if err := addDirectoryEntries(cfg.BundleDir, input.Artifacts.HostPackages.Path, "host-packages", &manifestEntries); err != nil {
			return Result{}, err
		}
	}

	pubEntry, err := describeFile(filepath.Join(cfg.BundleDir, publicKeyTarget), publicKeyTarget, "public-keys", false, "")
	if err != nil {
		return Result{}, err
	}
	manifestEntries = append(manifestEntries, pubEntry)

	if err := validateInstallableBundle(manifestEntries, cfg.Pack); err != nil {
		return Result{}, err
	}
	sort.Slice(manifestEntries, func(i, j int) bool { return manifestEntries[i].Path < manifestEntries[j].Path })

	supportedUpgradeSources := input.Compatibility.SupportedUpgradeSources
	if supportedUpgradeSources == nil {
		supportedUpgradeSources = []string{}
	}
	compatibility := map[string]any{
		"k3sVersion":              input.Compatibility.K3sVersion,
		"chartVersion":            input.Compatibility.ChartVersion,
		"supportedUpgradeSources": supportedUpgradeSources,
	}
	if strings.TrimSpace(input.Compatibility.ArtifactServerVersion) != "" {
		compatibility["artifactServerVersion"] = input.Compatibility.ArtifactServerVersion
	}
	if strings.TrimSpace(input.Compatibility.DnsVersion) != "" {
		compatibility["dnsVersion"] = input.Compatibility.DnsVersion
	}
	if strings.TrimSpace(input.Compatibility.InferenceVersion) != "" {
		compatibility["inferenceVersion"] = input.Compatibility.InferenceVersion
	}
	if strings.TrimSpace(input.Compatibility.WorkflowsVersion) != "" {
		compatibility["workflowsVersion"] = input.Compatibility.WorkflowsVersion
	}

	doc := manifestDoc{
		SchemaVersion: 1,
		BundleVersion: cfg.BundleVersion,
		ReleaseID:     input.ReleaseID,
		HostBaseline:  cfg.HostBaseline,
		BuiltAt:       time.Now().UTC().Format(time.RFC3339),
		Compatibility: compatibility,
		Runtimes:      runtimes,
		SigningKeyID:  cfg.SigningKeyID,
		Entries:       manifestEntries,
	}
	manifestBytes, err := json.Marshal(doc)
	if err != nil {
		return Result{}, fmt.Errorf("releasebundle: marshal release manifest: %w", err)
	}
	manifestPath := filepath.Join(cfg.BundleDir, "release-manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o640); err != nil {
		return Result{}, fmt.Errorf("releasebundle: write release-manifest.json: %w", err)
	}
	sig, err := verify.Sign(priv, manifestBytes)
	if err != nil {
		return Result{}, err
	}
	sigPath := filepath.Join(cfg.BundleDir, "release-manifest.sig")
	if err := os.WriteFile(sigPath, sig, 0o640); err != nil {
		return Result{}, fmt.Errorf("releasebundle: write release-manifest.sig: %w", err)
	}

	return Result{
		BundleDir:     cfg.BundleDir,
		BundleVersion: cfg.BundleVersion,
		ReleaseID:     input.ReleaseID,
		ManifestPath:  manifestPath,
		SignaturePath: sigPath,
		PublicKeyPath: filepath.Join(cfg.BundleDir, publicKeyTarget),
		EntryCount:    len(manifestEntries),
	}, nil
}

func isCanonicalArtifactServerReference(ref string) bool {
	const prefix = "registry.local/artifact-server@sha256:"
	if !strings.HasPrefix(ref, prefix) || len(ref) != len(prefix)+64 {
		return false
	}
	for _, c := range strings.TrimPrefix(ref, prefix) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isCanonicalHostAgentReference(ref string) bool {
	const prefix = "registry.local/appliance-host-agent@sha256:"
	if !strings.HasPrefix(ref, prefix) || len(ref) != len(prefix)+64 {
		return false
	}
	for _, c := range strings.TrimPrefix(ref, prefix) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isCanonicalDNSReference(ref string) bool {
	const prefix = "registry.local/coredns@sha256:"
	if !strings.HasPrefix(ref, prefix) || len(ref) != len(prefix)+64 {
		return false
	}
	for _, c := range strings.TrimPrefix(ref, prefix) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isCanonicalInferenceRuntimeReference(ref string) bool {
	const prefix = "registry.local/inference-runtime@sha256:"
	if !strings.HasPrefix(ref, prefix) || len(ref) != len(prefix)+64 {
		return false
	}
	for _, c := range strings.TrimPrefix(ref, prefix) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isCanonicalMessageBrokerReference(ref string) bool {
	const prefix = "registry.local/nats@sha256:"
	if !strings.HasPrefix(ref, prefix) || len(ref) != len(prefix)+64 {
		return false
	}
	for _, c := range strings.TrimPrefix(ref, prefix) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func VerifyBundle(bundleDir, publicKeyPath string) (*bundle.Bundle, error) {
	pub, err := verify.LoadPublicKey("release-signing-key", publicKeyPath)
	if err != nil {
		return nil, err
	}
	b, _, err := bundle.Load(bundleDir, &pub)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func prepareBundleDir(root string) error {
	if info, err := os.Stat(root); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("releasebundle: %s exists and is not a directory", root)
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return fmt.Errorf("releasebundle: read %s: %w", root, err)
		}
		if len(entries) > 0 {
			return fmt.Errorf("releasebundle: bundleDir %s must be empty", root)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("releasebundle: stat %s: %w", root, err)
	}
	return os.MkdirAll(root, 0o750)
}

func validateConfiguredEntry(entry EntryConfig) error {
	if entry.SourcePath == "" || entry.TargetPath == "" || entry.Component == "" {
		return fmt.Errorf("releasebundle: every entry requires sourcePath, targetPath, and component")
	}
	switch entry.Component {
	case "appliance", "k3s-binary", "k3s-install", "k3s-images", "oci-images", "chart", "kubernetes-crds", "configuration", "scanner-data", "sbom", "provenance", "notices", "public-keys", "tests", "host-packages", "artifacts":
	default:
		return fmt.Errorf("releasebundle: unsupported component %q", entry.Component)
	}
	if strings.HasPrefix(entry.TargetPath, "../") || strings.Contains(entry.TargetPath, "/../") {
		return fmt.Errorf("releasebundle: targetPath %q escapes the bundle root", entry.TargetPath)
	}
	return nil
}

func copyEntry(bundleDir string, entry EntryConfig) (manifestEntry, error) {
	srcInfo, err := os.Stat(entry.SourcePath)
	if err != nil {
		return manifestEntry{}, fmt.Errorf("releasebundle: stat %s: %w", entry.SourcePath, err)
	}
	if srcInfo.IsDir() {
		return manifestEntry{}, fmt.Errorf("releasebundle: configured entry %s must be a file, not a directory", entry.SourcePath)
	}
	destPath := filepath.Join(bundleDir, filepath.FromSlash(entry.TargetPath))
	if err := os.MkdirAll(filepath.Dir(destPath), 0o750); err != nil {
		return manifestEntry{}, fmt.Errorf("releasebundle: create %s: %w", filepath.Dir(destPath), err)
	}
	data, err := os.ReadFile(entry.SourcePath)
	if err != nil {
		return manifestEntry{}, fmt.Errorf("releasebundle: read %s: %w", entry.SourcePath, err)
	}
	mode := os.FileMode(0o640)
	if entry.Executable {
		mode = 0o750
	}
	if err := os.WriteFile(destPath, data, mode); err != nil {
		return manifestEntry{}, fmt.Errorf("releasebundle: write %s: %w", destPath, err)
	}
	return describeFile(destPath, entry.TargetPath, entry.Component, entry.Executable, entry.ImageReference)
}

func addDirectoryEntries(bundleDir, sourceDir, component string, manifestEntries *[]manifestEntry) error {
	if strings.TrimSpace(sourceDir) == "" {
		return nil
	}
	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		target := filepath.ToSlash(filepath.Join(component, rel))
		dest := filepath.Join(bundleDir, filepath.FromSlash(target))
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dest, data, 0o640); err != nil {
			return err
		}
		entry, err := describeFile(dest, target, component, false, "")
		if err != nil {
			return err
		}
		*manifestEntries = append(*manifestEntries, entry)
		return nil
	})
}

func describeFile(fullPath, relPath, component string, executable bool, imageReference string) (manifestEntry, error) {
	digest, err := verify.Digest(fullPath)
	if err != nil {
		return manifestEntry{}, err
	}
	info, err := os.Stat(fullPath)
	if err != nil {
		return manifestEntry{}, err
	}
	return manifestEntry{
		Path:           filepath.ToSlash(relPath),
		Component:      component,
		Digest:         digest,
		SizeBytes:      info.Size(),
		Executable:     executable,
		ImageReference: imageReference,
	}, nil
}

func validateInstallableBundle(entries []manifestEntry, pack string) error {
	counts := map[string]int{}
	for _, entry := range entries {
		counts[entry.Component]++
	}
	switch pack {
	case PackDevPlatform:
		var registryImage, dnsImage, registryChart, dnsChart bool
		for _, entry := range entries {
			registryImage = registryImage || (entry.Component == "oci-images" && isCanonicalArtifactServerReference(entry.ImageReference))
			dnsImage = dnsImage || (entry.Component == "oci-images" && isCanonicalDNSReference(entry.ImageReference))
			base := strings.ToLower(filepath.Base(entry.Path))
			registryChart = registryChart || (entry.Component == "chart" && strings.HasPrefix(base, "appliance-registry-"))
			dnsChart = dnsChart || (entry.Component == "chart" && strings.HasPrefix(base, "appliance-dns-"))
		}
		if !registryImage || !dnsImage || !registryChart || !dnsChart {
			return fmt.Errorf("releasebundle: dev-platform pack requires Artifact Server and CoreDNS images and charts")
		}
		if counts["chart"] == 0 {
			return fmt.Errorf("releasebundle: dev-platform pack is missing a workflows chart")
		}
		if counts["kubernetes-crds"] == 0 {
			return fmt.Errorf("releasebundle: dev-platform pack is missing kubernetes-crds")
		}
		if counts["oci-images"] == 0 {
			return fmt.Errorf("releasebundle: dev-platform pack must include at least one oci-images archive")
		}
		var hasWorkflowsChart bool
		for _, entry := range entries {
			if entry.Component != "chart" {
				continue
			}
			base := strings.ToLower(filepath.Base(entry.Path))
			if strings.Contains(base, "workflows") {
				hasWorkflowsChart = true
				break
			}
		}
		if !hasWorkflowsChart {
			return fmt.Errorf("releasebundle: dev-platform pack is missing a workflows chart")
		}
		return nil
	case PackDeviceUser:
		var hasHostAgentImage bool
		for _, entry := range entries {
			if entry.Component == "oci-images" && isCanonicalHostAgentReference(entry.ImageReference) {
				hasHostAgentImage = true
			}
		}
		if !hasHostAgentImage {
			return fmt.Errorf("releasebundle: deviceuser pack requires the in-cluster host-agent image")
		}
		return nil
	case PackStdLLMAMD64, PackAccLLMAMD64, PackAccLLMARM64:
		if counts["chart"] == 0 {
			return fmt.Errorf("releasebundle: %s pack is missing appliance-inference chart", pack)
		}
		if counts["oci-images"] == 0 {
			return fmt.Errorf("releasebundle: %s pack must include the inference-runtime image", pack)
		}
		var hasInferenceChart, hasInferenceImage bool
		for _, entry := range entries {
			base := strings.ToLower(filepath.Base(entry.Path))
			if entry.Component == "chart" && strings.HasPrefix(base, "appliance-inference-") {
				hasInferenceChart = true
			}
			if entry.Component == "oci-images" && isCanonicalInferenceRuntimeReference(entry.ImageReference) {
				hasInferenceImage = true
			}
		}
		if !hasInferenceChart {
			return fmt.Errorf("releasebundle: %s pack is missing appliance-inference chart", pack)
		}
		if !hasInferenceImage {
			return fmt.Errorf("releasebundle: %s pack is missing inference-runtime image", pack)
		}
		return nil
	}
	if pack == PackFoundation {
		var hasHostAgentDaemon, hasMDNSPackage bool
		for _, entry := range entries {
			hasHostAgentDaemon = hasHostAgentDaemon || (entry.Component == "appliance" && strings.EqualFold(filepath.Base(entry.Path), "appliance-host-agentd"))
			hasMDNSPackage = hasMDNSPackage || (entry.Component == "host-packages" && strings.Contains(strings.ToLower(filepath.Base(entry.Path)), "avahi-daemon"))
		}
		if !hasHostAgentDaemon || !hasMDNSPackage {
			return fmt.Errorf("releasebundle: foundation pack requires host-agent daemon and Avahi mDNS package")
		}
	}

	requiredSingles := []string{"appliance", "k3s-binary", "chart", "configuration"}
	for _, component := range requiredSingles {
		if counts[component] == 0 {
			return fmt.Errorf("releasebundle: assembled bundle is missing required component %q", component)
		}
	}
	if counts["k3s-images"] == 0 {
		return fmt.Errorf("releasebundle: assembled bundle must include at least one k3s-images archive")
	}
	if counts["oci-images"] == 0 {
		return fmt.Errorf("releasebundle: assembled bundle must include at least one oci-images archive")
	}
	return nil
}

// entryBelongsToPack reports whether a configured entry should be included in
// the assembled pack. Empty pack means legacy full bundle (everything).
func entryBelongsToPack(entry EntryConfig, pack string) bool {
	switch pack {
	case "":
		return true
	case PackFoundation:
		return !entryIsStorageNetwork(entry) && !entryIsBuildWorkflows(entry) && !entryIsDeviceUser(entry) && !entryIsInference(entry)
	case PackDevPlatform:
		return entryIsStorageNetwork(entry) || entryIsBuildWorkflows(entry)
	case PackDeviceUser:
		return entryIsDeviceUser(entry)
	case PackStdLLMAMD64, PackAccLLMAMD64, PackAccLLMARM64:
		return entryIsInference(entry)
	default:
		return false
	}
}

func entryIsBuildWorkflows(entry EntryConfig) bool {
	target := strings.ToLower(filepath.ToSlash(entry.TargetPath))
	ref := strings.ToLower(strings.TrimSpace(entry.ImageReference))
	base := strings.ToLower(filepath.Base(target))
	sourceBase := strings.ToLower(filepath.Base(entry.SourcePath))

	if strings.HasPrefix(target, "kubernetes/crds/") || entry.Component == "kubernetes-crds" {
		return true
	}
	if entry.Component == "chart" && (strings.Contains(base, "workflows") || strings.Contains(sourceBase, "workflows")) {
		return true
	}
	if strings.Contains(ref, "workflow-controller") || strings.Contains(ref, "argoexec") ||
		strings.Contains(ref, "workflow-executor") || strings.Contains(base, "workflow-controller") ||
		strings.Contains(base, "workflow-executor") || strings.Contains(sourceBase, "workflow-controller") ||
		strings.Contains(sourceBase, "workflow-executor") {
		return true
	}
	if strings.Contains(ref, "workspace-provisioner") || strings.Contains(target, "workspace-provisioner") ||
		strings.Contains(sourceBase, "workspace-provisioner") {
		return true
	}
	return false
}

func entryIsStorageNetwork(entry EntryConfig) bool {
	target := strings.ToLower(filepath.ToSlash(entry.TargetPath))
	ref := strings.ToLower(strings.TrimSpace(entry.ImageReference))
	base := strings.ToLower(filepath.Base(target))
	sourceBase := strings.ToLower(filepath.Base(entry.SourcePath))
	if strings.Contains(ref, "artifact-server") || strings.Contains(target, "artifact-server") ||
		strings.Contains(sourceBase, "artifact-server") ||
		(entry.Component == "chart" && (strings.HasPrefix(base, "appliance-registry-") || strings.HasPrefix(sourceBase, "appliance-registry-"))) {
		return true
	}
	if strings.Contains(ref, "/coredns") || strings.Contains(target, "coredns") ||
		strings.Contains(sourceBase, "coredns") ||
		(entry.Component == "chart" && (strings.HasPrefix(base, "appliance-dns-") || strings.HasPrefix(sourceBase, "appliance-dns-"))) {
		return true
	}
	return false
}

func entryIsDeviceUser(entry EntryConfig) bool {
	target := strings.ToLower(filepath.ToSlash(entry.TargetPath))
	ref := strings.ToLower(strings.TrimSpace(entry.ImageReference))
	sourceBase := strings.ToLower(filepath.Base(entry.SourcePath))

	return strings.Contains(ref, "appliance-host-agent") ||
		strings.HasPrefix(ref, "registry.local/jellyfin@sha256:") || strings.Contains(target, "jellyfin") || strings.Contains(sourceBase, "jellyfin")
}

func entryIsInference(entry EntryConfig) bool {
	target := strings.ToLower(filepath.ToSlash(entry.TargetPath))
	ref := strings.ToLower(strings.TrimSpace(entry.ImageReference))
	base := strings.ToLower(filepath.Base(target))
	sourceBase := strings.ToLower(filepath.Base(entry.SourcePath))

	if strings.Contains(ref, "inference-runtime") || strings.Contains(target, "inference-runtime") ||
		strings.Contains(sourceBase, "inference-runtime") {
		return true
	}
	if entry.Component == "chart" && (strings.HasPrefix(base, "appliance-inference-") ||
		strings.HasPrefix(sourceBase, "appliance-inference-") || strings.Contains(base, "inference")) {
		return true
	}
	return false
}

func encodePublicKeyPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("releasebundle: marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
