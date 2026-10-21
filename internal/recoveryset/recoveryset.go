// Package recoveryset defines the PostgreSQL-aware disaster-recovery boundary.
// It is intentionally separate from portable desired-configuration archives.
package recoveryset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/lifecycle"
)

const Format = "zon.recovery-set/v1"

// Manifest names every declared recovery artifact. No implementation may
// silently treat a live PGDATA copy as a database backup.
type Manifest struct {
	Format               string           `json:"format"`
	ID                   string           `json:"id"`
	CreatedAt            time.Time        `json:"createdAt"`
	PlatformVersion      string           `json:"platformVersion"`
	Database             DatabaseArtifact `json:"database"`
	ConfigurationArchive string           `json:"configurationArchive,omitempty"`
	ConfigurationSHA256  string           `json:"configurationSha256,omitempty"`
	Artifacts            []Artifact       `json:"artifacts,omitempty"`
}

// Artifact is an additional recovery-set member. Paths are always relative
// to the recovery-set root; this prevents a manifest from being used to read
// an arbitrary host file during verification or restore.
type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type DatabaseArtifact struct {
	Engine string `json:"engine"`
	Format string `json:"format"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// LogicalDatabaseExporter streams a consistent logical database artifact and
// verifies restore in an isolated PostgreSQL target before it is accepted.
// Platform adapters may use local Kubernetes or a managed cloud provider,
// but retain this exact safety contract.
type LogicalDatabaseExporter interface {
	Export(context.Context, string) (DatabaseArtifact, error)
	VerifyRestore(context.Context, DatabaseArtifact) error
}

func (m Manifest) Validate() error {
	if m.Format != Format || m.ID == "" || m.CreatedAt.IsZero() {
		return errors.New("recovery set: invalid manifest identity")
	}
	if m.Database.Engine != "postgres" || (m.Database.Format != "custom" && m.Database.Format != "directory") || m.Database.Path == "" || len(m.Database.SHA256) != 64 {
		return fmt.Errorf("recovery set: invalid PostgreSQL logical artifact")
	}
	if filepath.IsAbs(m.Database.Path) || strings.HasPrefix(filepath.Clean(m.Database.Path), ".."+string(filepath.Separator)) {
		return fmt.Errorf("recovery set: invalid PostgreSQL logical artifact path")
	}
	if _, err := hex.DecodeString(m.Database.SHA256); err != nil {
		return fmt.Errorf("recovery set: invalid PostgreSQL logical artifact checksum")
	}
	for _, a := range m.Artifacts {
		if err := validateArtifact(a); err != nil {
			return err
		}
	}
	if m.ConfigurationArchive != "" {
		if err := validateArtifact(Artifact{Path: m.ConfigurationArchive, SHA256: m.ConfigurationSHA256}); err != nil {
			return fmt.Errorf("recovery set: invalid configuration archive: %w", err)
		}
	}
	return nil
}

func validateArtifact(a Artifact) error {
	if a.Path == "" || filepath.IsAbs(a.Path) || strings.HasPrefix(filepath.Clean(a.Path), ".."+string(filepath.Separator)) || len(a.SHA256) != 64 {
		return fmt.Errorf("recovery set: invalid artifact")
	}
	if _, err := hex.DecodeString(a.SHA256); err != nil {
		return fmt.Errorf("recovery set: invalid artifact checksum")
	}
	return nil
}

func manifestPath(root string) string { return filepath.Join(root, "manifest.json") }

// Save writes the declaration only after all artifacts have been generated
// and verified. Atomic publication means an interrupted backup is never
// mistaken for a usable recovery point.
func Save(root string, m Manifest) error {
	if err := m.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("recovery set: encode manifest: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("recovery set: create root: %w", err)
	}
	return lifecycle.WriteFileAtomic(manifestPath(root), append(data, '\n'), 0o600)
}

func Load(root string) (Manifest, error) {
	data, err := os.ReadFile(manifestPath(root))
	if err != nil {
		return Manifest{}, fmt.Errorf("recovery set: read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("recovery set: parse manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// ChecksumFile computes an artifact checksum without loading a potentially
// large database dump into the zonctl process.
func ChecksumFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyFiles confirms every declared member is still inside root and has the
// exact digest in the manifest. The database artifact is deliberately checked
// here too; restore adapters must call this before touching a target.
func VerifyFiles(root string, m Manifest) error {
	if err := m.Validate(); err != nil {
		return err
	}
	entries := append([]Artifact{{Path: m.Database.Path, SHA256: m.Database.SHA256}}, m.Artifacts...)
	if m.ConfigurationArchive != "" {
		entries = append(entries, Artifact{Path: m.ConfigurationArchive, SHA256: m.ConfigurationSHA256})
	}
	for _, entry := range entries {
		if entry.Path == "" || filepath.IsAbs(entry.Path) || strings.HasPrefix(filepath.Clean(entry.Path), ".."+string(filepath.Separator)) {
			return fmt.Errorf("recovery set: unsafe artifact path %q", entry.Path)
		}
		path := filepath.Join(root, entry.Path)
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("recovery set: artifact %q is missing or not a regular file", entry.Path)
		}
		if entry.SHA256 != "" {
			sum, err := ChecksumFile(path)
			if err != nil || sum != entry.SHA256 {
				return fmt.Errorf("recovery set: artifact checksum mismatch for %q", entry.Path)
			}
		}
	}
	return nil
}
