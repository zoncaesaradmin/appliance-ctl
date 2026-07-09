package backup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

// Create takes a coordinated backup: stop K3s for a consistent snapshot,
// copy dataDir into a new timestamped directory under backupRoot,
// digest every file, write the manifest, then restart K3s. It always
// attempts to restart K3s, even when the copy fails, so a failed backup
// does not leave the appliance down.
func Create(ctx context.Context, ops k3s.Ops, unitName, dataDir, backupRoot, applianceVersion string) (*Manifest, []evidence.Check, error) {
	var checks []evidence.Check
	createdAt := time.Now().UTC()

	stopStart := time.Now()
	if err := ops.Stop(unitName); err != nil {
		return nil, checks, fmt.Errorf("backup: stop k3s: %w", err)
	}
	checks = append(checks, evidence.Check{
		ID: "backup-stop-k3s", Category: "backup-restore", Status: evidence.StatusPass,
		Message: "k3s stopped for a consistent snapshot", Timestamp: stopStart.UTC(),
		DurationMs: time.Since(stopStart).Milliseconds(), Idempotent: true, SecretsRedacted: true,
	})

	backupID := newBackupID()
	backupDir := filepath.Join(backupRoot, backupID)

	copyStart := time.Now()
	files, copyErr := copyDir(dataDir, filepath.Join(backupDir, "data"))
	copyCheck := evidence.Check{
		ID: "backup-copy-data", Category: "backup-restore", Timestamp: copyStart.UTC(),
		DurationMs: time.Since(copyStart).Milliseconds(), Idempotent: true, SecretsRedacted: true,
	}
	if copyErr != nil {
		copyCheck.Status = evidence.StatusFail
		copyCheck.Message = copyErr.Error()
		checks = append(checks, copyCheck)
		_ = ops.EnableAndStart(unitName)
		return nil, checks, fmt.Errorf("backup: %w", copyErr)
	}
	copyCheck.Status = evidence.StatusPass
	copyCheck.Message = fmt.Sprintf("copied %d file(s) from %s", len(files), dataDir)
	checks = append(checks, copyCheck)

	manifest := &Manifest{BackupID: backupID, CreatedAt: createdAt, ApplianceVersion: applianceVersion, Files: files}
	if err := SaveManifest(backupDir, manifest); err != nil {
		_ = ops.EnableAndStart(unitName)
		return nil, checks, fmt.Errorf("backup: %w", err)
	}

	startStart := time.Now()
	startCheck := evidence.Check{
		ID: "backup-restart-k3s", Category: "backup-restore", Timestamp: startStart.UTC(),
		Idempotent: true, SecretsRedacted: true,
	}
	if err := ops.EnableAndStart(unitName); err != nil {
		startCheck.Status = evidence.StatusFail
		startCheck.Message = err.Error()
		startCheck.DurationMs = time.Since(startStart).Milliseconds()
		checks = append(checks, startCheck)
		return manifest, checks, fmt.Errorf("backup: restart k3s: %w", err)
	}
	startCheck.Status = evidence.StatusPass
	startCheck.Message = "k3s restarted after backup"
	startCheck.DurationMs = time.Since(startStart).Milliseconds()
	checks = append(checks, startCheck)

	return manifest, checks, nil
}

// Verify recomputes the digest of every file the manifest at backupDir
// describes and fails closed on any mismatch or missing file: a
// corrupted or tampered backup is never treated as usable.
func Verify(backupDir string) ([]evidence.Check, error) {
	manifest, err := LoadManifest(backupDir)
	if err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}

	dataDir := filepath.Join(backupDir, "data")
	var checks []evidence.Check
	var failures []error

	for _, f := range manifest.Files {
		path := filepath.Join(dataDir, f.Path)
		check := evidence.Check{
			ID: "backup-verify-" + evidence.SanitizeIDSegment(f.Path), Category: "backup-restore",
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		}
		if err := verify.VerifyDigest(path, f.Digest); err != nil {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			failures = append(failures, fmt.Errorf("%s: %w", f.Path, err))
		} else {
			check.Status = evidence.StatusPass
			check.Message = f.Path + " digest matches"
		}
		checks = append(checks, check)
	}

	if len(failures) > 0 {
		return checks, fmt.Errorf("backup: %d file(s) failed integrity verification: %w", len(failures), errors.Join(failures...))
	}
	return checks, nil
}

// Restore verifies the backup's integrity first and refuses to proceed
// if it fails, then stops K3s, replaces dataDir with the verified
// snapshot, and restarts K3s. This is a clean-node restore: dataDir is
// fully replaced, not merged.
func Restore(ctx context.Context, ops k3s.Ops, unitName, backupDir, dataDir string) ([]evidence.Check, error) {
	checks, err := Verify(backupDir)
	if err != nil {
		return checks, fmt.Errorf("backup: refusing to restore from a backup that failed integrity verification: %w", err)
	}

	stopStart := time.Now()
	if err := ops.Stop(unitName); err != nil {
		return checks, fmt.Errorf("backup: stop k3s: %w", err)
	}
	checks = append(checks, evidence.Check{
		ID: "restore-stop-k3s", Category: "backup-restore", Status: evidence.StatusPass,
		Message: "k3s stopped for restore", Timestamp: stopStart.UTC(),
		DurationMs: time.Since(stopStart).Milliseconds(), Idempotent: true, SecretsRedacted: true,
	})

	if err := os.RemoveAll(dataDir); err != nil {
		_ = ops.EnableAndStart(unitName)
		return checks, fmt.Errorf("backup: clear data directory: %w", err)
	}

	restoreStart := time.Now()
	restoreCheck := evidence.Check{
		ID: "restore-copy-data", Category: "backup-restore", Timestamp: restoreStart.UTC(),
		Idempotent: true, SecretsRedacted: true,
	}
	if _, err := copyDir(filepath.Join(backupDir, "data"), dataDir); err != nil {
		restoreCheck.Status = evidence.StatusFail
		restoreCheck.Message = err.Error()
		restoreCheck.DurationMs = time.Since(restoreStart).Milliseconds()
		checks = append(checks, restoreCheck)
		_ = ops.EnableAndStart(unitName)
		return checks, fmt.Errorf("backup: restore data: %w", err)
	}
	restoreCheck.Status = evidence.StatusPass
	restoreCheck.Message = "data restored from backup"
	restoreCheck.DurationMs = time.Since(restoreStart).Milliseconds()
	checks = append(checks, restoreCheck)

	startStart := time.Now()
	startCheck := evidence.Check{
		ID: "restore-start-k3s", Category: "backup-restore", Timestamp: startStart.UTC(),
		Idempotent: true, SecretsRedacted: true,
	}
	if err := ops.EnableAndStart(unitName); err != nil {
		startCheck.Status = evidence.StatusFail
		startCheck.Message = err.Error()
		startCheck.DurationMs = time.Since(startStart).Milliseconds()
		checks = append(checks, startCheck)
		return checks, fmt.Errorf("backup: start k3s: %w", err)
	}
	startCheck.Status = evidence.StatusPass
	startCheck.Message = "k3s restarted after restore"
	startCheck.DurationMs = time.Since(startStart).Milliseconds()
	checks = append(checks, startCheck)

	return checks, nil
}

// copyDir recursively copies src into dst, returning a FileEntry (path
// relative to src, digest, size) for every regular file copied.
func copyDir(src, dst string) ([]FileEntry, error) {
	var entries []FileEntry

	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if rel == "." {
				return os.MkdirAll(dst, 0o750)
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o750)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		destPath := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(destPath), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(destPath, data, 0o640); err != nil {
			return err
		}

		digest, err := verify.Digest(destPath)
		if err != nil {
			return err
		}
		entries = append(entries, FileEntry{Path: rel, Digest: digest, SizeBytes: int64(len(data))})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("backup: copy %s to %s: %w", src, dst, err)
	}
	return entries, nil
}
