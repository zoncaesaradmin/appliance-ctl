package backup_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/backup"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
)

type fakeK3s struct {
	stopCalls  int
	startCalls int
	stopErr    error
	startErr   error
}

func (f *fakeK3s) ops() k3s.Ops {
	return k3s.Ops{
		Stop: func(string) error {
			f.stopCalls++
			return f.stopErr
		},
		EnableAndStart: func(string) error {
			f.startCalls++
			return f.startErr
		},
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
}

func statusOf(t *testing.T, checks []evidence.Check, id string) evidence.Status {
	t.Helper()
	for _, c := range checks {
		if c.ID == id {
			return c.Status
		}
	}
	t.Fatalf("no check with id %q found", id)
	return ""
}

func readAll(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(data)
	}
	return out
}

// Automated offline RPO/RTO drill: back up a live data directory,
// simulate a disaster (corruption + data loss), restore, and prove the
// restored data is byte-for-byte identical to the backed-up snapshot,
// with durations recorded as evidence for RPO/RTO reporting.
func TestBackupRestore_RPO_RTO_Drill(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "live-data")
	backupRoot := filepath.Join(root, "backups")

	writeFile(t, filepath.Join(dataDir, "state.db"), "k3s datastore contents")
	writeFile(t, filepath.Join(dataDir, "server", "tls", "server-ca.crt"), "fake CA cert")
	original := readAll(t, dataDir)

	fake := &fakeK3s{}
	manifest, createChecks, err := backup.Create(context.Background(), fake.ops(), "k3s.service", dataDir, backupRoot, "2.4.0")
	if err != nil {
		t.Fatalf("backup.Create failed: %v", err)
	}
	if fake.stopCalls != 1 || fake.startCalls != 1 {
		t.Errorf("expected exactly one stop and one restart during backup, got stop=%d start=%d", fake.stopCalls, fake.startCalls)
	}
	for _, id := range []string{"backup-stop-k3s", "backup-copy-data", "backup-restart-k3s"} {
		if got := statusOf(t, createChecks, id); got != evidence.StatusPass {
			t.Errorf("check %q: expected pass, got %s", id, got)
		}
	}
	if len(manifest.Files) != 2 {
		t.Fatalf("expected 2 files captured, got %d", len(manifest.Files))
	}

	// Disaster: the live data directory is lost/corrupted.
	if err := os.RemoveAll(dataDir); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dataDir, "state.db"), "corrupted garbage")

	backupDir := filepath.Join(backupRoot, manifest.BackupID)
	restoreChecks, err := backup.Restore(context.Background(), fake.ops(), "k3s.service", backupDir, dataDir)
	if err != nil {
		t.Fatalf("backup.Restore failed: %v", err)
	}
	if fake.stopCalls != 2 || fake.startCalls != 2 {
		t.Errorf("expected a second stop/restart pair during restore, got stop=%d start=%d", fake.stopCalls, fake.startCalls)
	}
	for _, id := range []string{"restore-stop-k3s", "restore-copy-data", "restore-start-k3s"} {
		if got := statusOf(t, restoreChecks, id); got != evidence.StatusPass {
			t.Errorf("check %q: expected pass, got %s", id, got)
		}
	}

	// RPO: the restored data must be identical to what was backed up,
	// not just present.
	restored := readAll(t, dataDir)
	if len(restored) != len(original) {
		t.Fatalf("expected %d restored files, got %d", len(original), len(restored))
	}
	for name, content := range original {
		if restored[name] != content {
			t.Errorf("file %q: restored content %q does not match original %q", name, restored[name], content)
		}
	}

	// RTO evidence: every stage recorded a duration, so recovery time is
	// measurable and reportable, not just "it worked."
	for _, c := range append(createChecks, restoreChecks...) {
		if c.DurationMs < 0 {
			t.Errorf("check %q: expected a non-negative duration, got %d", c.ID, c.DurationMs)
		}
	}
}

// Integrity evidence: a backup whose file no longer matches its
// manifest digest must never be restored, and restore must not touch
// the live host before verification completes.
func TestRestore_RefusesTamperedBackup(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "live-data")
	backupRoot := filepath.Join(root, "backups")
	writeFile(t, filepath.Join(dataDir, "state.db"), "original contents")

	fake := &fakeK3s{}
	manifest, _, err := backup.Create(context.Background(), fake.ops(), "k3s.service", dataDir, backupRoot, "2.4.0")
	if err != nil {
		t.Fatal(err)
	}

	backupDir := filepath.Join(backupRoot, manifest.BackupID)
	tamperedFile := filepath.Join(backupDir, "data", "state.db")
	if err := os.WriteFile(tamperedFile, []byte("tampered backup contents"), 0o640); err != nil {
		t.Fatal(err)
	}

	fake.stopCalls, fake.startCalls = 0, 0 // reset after Create's own stop/start
	if _, err := backup.Restore(context.Background(), fake.ops(), "k3s.service", backupDir, dataDir); err == nil {
		t.Fatal("expected restore to refuse a tampered backup")
	}
	if fake.stopCalls != 0 {
		t.Errorf("expected restore to fail before ever stopping k3s, got %d stop calls", fake.stopCalls)
	}

	live, err := os.ReadFile(filepath.Join(dataDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if string(live) != "original contents" {
		t.Error("expected the live data directory to be untouched after a refused restore")
	}
}

// Missing evidence: a backup file the manifest describes was deleted
// from disk.
func TestVerify_MissingFileFailsClosed(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "live-data")
	backupRoot := filepath.Join(root, "backups")
	writeFile(t, filepath.Join(dataDir, "state.db"), "contents")

	fake := &fakeK3s{}
	manifest, _, err := backup.Create(context.Background(), fake.ops(), "k3s.service", dataDir, backupRoot, "2.4.0")
	if err != nil {
		t.Fatal(err)
	}

	backupDir := filepath.Join(backupRoot, manifest.BackupID)
	if err := os.Remove(filepath.Join(backupDir, "data", "state.db")); err != nil {
		t.Fatal(err)
	}

	if _, err := backup.Verify(backupDir); err == nil {
		t.Error("expected verify to fail when a backed-up file is missing")
	}
}

func TestCreate_RestartsK3sEvenWhenCopyFails(t *testing.T) {
	root := t.TempDir()
	backupRoot := filepath.Join(root, "backups")
	missingDataDir := filepath.Join(root, "does-not-exist")

	fake := &fakeK3s{}
	if _, _, err := backup.Create(context.Background(), fake.ops(), "k3s.service", missingDataDir, backupRoot, "2.4.0"); err == nil {
		t.Fatal("expected backup of a missing data directory to fail")
	}
	if fake.startCalls != 1 {
		t.Errorf("expected k3s to be restarted even though the backup failed, got %d start calls", fake.startCalls)
	}
}
