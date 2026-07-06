// Package backup implements coordinated backup and clean-node restore:
// stopping K3s for a consistent snapshot, copying its data directory,
// recording a digest per file, and restarting K3s. Restore verifies the
// backup's integrity before touching anything, then replaces the data
// directory from the verified snapshot.
package backup

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/lifecycle"
)

// FileEntry is one file captured in a backup, with Path relative to the
// backup's data root.
type FileEntry struct {
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	SizeBytes int64  `json:"sizeBytes"`
}

// Manifest describes one backup: when it was taken, by which appliance
// version, and the digest of every file it captured.
type Manifest struct {
	BackupID         string      `json:"backupId"`
	CreatedAt        time.Time   `json:"createdAt"`
	ApplianceVersion string      `json:"applianceVersion"`
	Files            []FileEntry `json:"files"`
}

func newBackupID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "backup-" + hex.EncodeToString(b[:])
}

// manifestPath is where a backup's manifest lives within its own
// directory, so Restore only needs the backup's root path.
func manifestPath(backupDir string) string {
	return filepath.Join(backupDir, "manifest.json")
}

// SaveManifest writes m atomically to backupDir/manifest.json.
func SaveManifest(backupDir string, m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("backup: marshal manifest: %w", err)
	}
	if err := os.MkdirAll(backupDir, 0o750); err != nil {
		return fmt.Errorf("backup: create backup directory: %w", err)
	}
	return lifecycle.WriteFileAtomic(manifestPath(backupDir), data, 0o640)
}

// LoadManifest reads backupDir/manifest.json.
func LoadManifest(backupDir string) (*Manifest, error) {
	data, err := os.ReadFile(manifestPath(backupDir))
	if err != nil {
		return nil, fmt.Errorf("backup: read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("backup: parse manifest: %w", err)
	}
	return &m, nil
}
