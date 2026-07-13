package releasebundle

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
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

type Config struct {
	SchemaVersion         int           `json:"schemaVersion"`
	BundleVersion         string        `json:"bundleVersion"`
	ReleaseInputDir       string        `json:"releaseInputDir"`
	BundleDir             string        `json:"bundleDir"`
	SigningKeyID          string        `json:"signingKeyId"`
	SigningPrivateKeyPath string        `json:"signingPrivateKeyPath"`
	HostBaseline          HostBaseline  `json:"hostBaseline"`
	Entries               []EntryConfig `json:"entries"`
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
	SchemaVersion int             `json:"schemaVersion"`
	BundleVersion string          `json:"bundleVersion"`
	ReleaseID     string          `json:"releaseId"`
	HostBaseline  HostBaseline    `json:"hostBaseline"`
	BuiltAt       string          `json:"builtAt"`
	Compatibility any             `json:"compatibility"`
	SigningKeyID  string          `json:"signingKeyId"`
	Entries       []manifestEntry `json:"entries"`
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
		entryByTarget[target] = entry
	}

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

	configSchemaTarget := "configuration/configuration.schema.json"
	if _, exists := entryByTarget[configSchemaTarget]; !exists {
		entryByTarget[configSchemaTarget] = EntryConfig{
			SourcePath: input.Artifacts.ConfigurationSchema.Path,
			TargetPath: configSchemaTarget,
			Component:  "configuration",
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

	pubEntry, err := describeFile(filepath.Join(cfg.BundleDir, publicKeyTarget), publicKeyTarget, "public-keys", false, "")
	if err != nil {
		return Result{}, err
	}
	manifestEntries = append(manifestEntries, pubEntry)

	if err := validateInstallableBundle(manifestEntries); err != nil {
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
	if strings.TrimSpace(input.Compatibility.ArgoVersion) != "" {
		compatibility["argoVersion"] = input.Compatibility.ArgoVersion
	}

	doc := manifestDoc{
		SchemaVersion: 1,
		BundleVersion: cfg.BundleVersion,
		ReleaseID:     input.ReleaseID,
		HostBaseline:  cfg.HostBaseline,
		BuiltAt:       time.Now().UTC().Format(time.RFC3339),
		Compatibility: compatibility,
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
	case "appliance", "k3s-binary", "k3s-install", "k3s-images", "oci-images", "chart", "kubernetes-crds", "configuration", "scanner-data", "sbom", "provenance", "notices", "public-keys", "tests":
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

func validateInstallableBundle(entries []manifestEntry) error {
	counts := map[string]int{}
	for _, entry := range entries {
		counts[entry.Component]++
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

func encodePublicKeyPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("releasebundle: marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
