package main

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/configarchive"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdirs"
	"github.com/zoncaesaradmin/appliance-ctl/internal/recoveryset"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

// runPostgresRecoveryBackup creates a portable, declared recovery set. It
// intentionally does not copy PGDATA or K3s state: those host-local files
// are neither crash-consistent nor meaningful for a managed/cloud database.
func runPostgresRecoveryBackup(ctx context.Context, opts cliOptions, installed *state.InstalledState, logger *slog.Logger, result commandResult) commandResult {
	if strings.TrimSpace(opts.recoverySetPath) == "" {
		return finish(result, "failed", 1, "backup: PostgreSQL requires --recovery-set <empty destination directory>; legacy K3s-directory backups are not valid", nil)
	}
	if strings.TrimSpace(installed.Components.PostgresImageReference) == "" {
		return finish(result, "failed", 1, "backup: installed state has no pinned PostgreSQL image reference", nil)
	}
	if _, _, _, err := configurationCommandInputs(opts); err != nil {
		return finish(result, "failed", 1, "backup: configuration archive inputs: "+err.Error(), nil)
	}
	if opts.dryRun {
		return finish(result, "succeeded", 0, "PostgreSQL recovery-set inputs validated (dry run)", nil)
	}
	root, err := prepareRecoverySetRoot(opts.recoverySetPath)
	if err != nil {
		return finish(result, "failed", 1, "backup: "+err.Error(), nil)
	}
	id, err := newRecoverySetID()
	if err != nil {
		return finish(result, "failed", 1, "backup: "+err.Error(), nil)
	}

	endpoint, token, key, err := configurationCommandInputs(opts)
	if err != nil {
		return finish(result, "failed", 1, "backup: "+err.Error(), nil)
	}
	revision, err := captureConfiguration(ctx, endpoint, token)
	if err != nil {
		return finish(result, "failed", 1, "backup: capture configuration: "+err.Error(), nil)
	}
	archive, _, err := configarchive.Seal(revision.ID, revision.SchemaVersion, revision.Payload, key)
	if err != nil {
		return finish(result, "failed", 1, "backup: seal configuration archive: "+err.Error(), nil)
	}
	configPath := filepath.Join(root, "configuration.zonconfig")
	if err := writeProtectedArchive(configPath, archive); err != nil {
		return finish(result, "failed", 1, "backup: write configuration archive: "+err.Error(), nil)
	}

	dumpPath := filepath.Join(root, "database.dump")
	exporter := recoveryset.KubernetesPostgresExporter{Kubeconfig: defaultKubeconfigPath, Namespace: "ace-infra", StatefulSet: "controlplane-database", Image: installed.Components.PostgresImageReference}
	database, err := exporter.Export(ctx, dumpPath)
	if err != nil {
		return finish(result, "failed", 1, "backup: "+err.Error(), nil)
	}
	if err := exporter.VerifyRestore(ctx, database); err != nil {
		return finish(result, "failed", 1, "backup: rejected un-restorable PostgreSQL dump: "+err.Error(), nil)
	}

	// Blob storage is the only v1 user-data domain. It is deliberately
	// archived separately from PostgreSQL so its scope is visible in the
	// manifest and can grow through component-owned exporters later.
	blobPath := filepath.Join(root, "blob-storage.tar")
	if err := archiveDirectory(hostdirs.BlobStorageDir, blobPath); err != nil {
		return finish(result, "failed", 1, "backup: archive blob storage: "+err.Error(), nil)
	}
	blobSum, err := recoveryset.ChecksumFile(blobPath)
	if err != nil {
		return finish(result, "failed", 1, "backup: checksum blob storage archive: "+err.Error(), nil)
	}

	receiptPath := filepath.Join(root, "installed-state.json")
	if err := copyProtectedFile(installedStatePath(opts.stateDir), receiptPath); err != nil {
		return finish(result, "failed", 1, "backup: copy installation receipt: "+err.Error(), nil)
	}
	configSum, _ := recoveryset.ChecksumFile(configPath)
	receiptSum, _ := recoveryset.ChecksumFile(receiptPath)
	policy := []byte("This system backup contains a verified PostgreSQL logical dump, encrypted desired configuration, blob-storage objects, and the installation receipt. The configuration key is deliberately operator-held and is not stored beside its ciphertext. Workspace source trees, build caches, models, logs, and registry caches are excluded.\n")
	policyPath := filepath.Join(root, "RECOVERY-SCOPE.txt")
	if err := os.WriteFile(policyPath, policy, 0o600); err != nil {
		return finish(result, "failed", 1, "backup: write recovery scope: "+err.Error(), nil)
	}
	policySum, _ := recoveryset.ChecksumFile(policyPath)
	manifest := recoveryset.Manifest{Format: recoveryset.Format, ID: id, CreatedAt: time.Now().UTC(), PlatformVersion: installed.InstalledVersion,
		Database:             recoveryset.DatabaseArtifact{Engine: database.Engine, Format: database.Format, Path: "database.dump", SHA256: database.SHA256},
		ConfigurationArchive: "configuration.zonconfig", ConfigurationSHA256: configSum,
		Artifacts: []recoveryset.Artifact{{Path: "blob-storage.tar", SHA256: blobSum}, {Path: "installed-state.json", SHA256: receiptSum}, {Path: "RECOVERY-SCOPE.txt", SHA256: policySum}},
	}
	if err := recoveryset.Save(root, manifest); err != nil {
		return finish(result, "failed", 1, "backup: "+err.Error(), nil)
	}
	if err := recoveryset.VerifyFiles(root, manifest); err != nil {
		return finish(result, "failed", 1, "backup: final recovery-set verification: "+err.Error(), nil)
	}
	data, _ := json.Marshal(map[string]string{"recoverySetId": id, "path": root, "databaseChecksum": database.SHA256, "configurationRevisionId": revision.ID})
	logger.Info("PostgreSQL recovery set complete", "recoverySetId", id, "path", root)
	return finish(result, "succeeded", 0, "verified PostgreSQL recovery set created", data)
}

// archiveDirectory writes a path-safe regular-file archive. Appliance paths
// are controlled by hostdirs; symlinks and special files are refused so a
// backup cannot capture data outside its declared storage boundary.
func archiveDirectory(source, destination string) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", source)
	}
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	w := tar.NewWriter(out)
	defer w.Close()
	return filepath.Walk(source, func(path string, entry os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Mode()&os.ModeSymlink != 0 || !entry.Mode().IsRegular() && !entry.IsDir() {
			return fmt.Errorf("unsupported blob-storage entry %s", path)
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		h, err := tar.FileInfoHeader(entry, "")
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(rel)
		if err := w.WriteHeader(h); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(w, in)
		return err
	})
}

func prepareRecoverySetRoot(path string) (string, error) {
	root, err := filepath.Abs(path)
	if err != nil || root == string(filepath.Separator) {
		return "", fmt.Errorf("invalid recovery-set destination")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("create recovery-set destination: %w", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	if len(entries) != 0 {
		return "", fmt.Errorf("recovery-set destination must be empty")
	}
	return root, nil
}

func newRecoverySetID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "recovery-" + time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b), nil
}

func copyProtectedFile(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
