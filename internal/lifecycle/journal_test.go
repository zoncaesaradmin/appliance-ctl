package lifecycle_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/lifecycle"
)

func TestJournal_BeginCurrentComplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transaction.json")
	journal := lifecycle.NewJournal(path, false)

	if current, err := journal.Current(); err != nil || current != nil {
		t.Fatalf("expected no current transaction on a fresh journal, got %+v, err=%v", current, err)
	}

	txn, err := journal.Begin("install", "", "2.4.0")
	if err != nil {
		t.Fatal(err)
	}
	if txn.ID == "" {
		t.Error("expected a non-empty transaction ID")
	}

	current, err := journal.Current()
	if err != nil {
		t.Fatal(err)
	}
	if current == nil || current.Status != lifecycle.StatusInProgress {
		t.Fatalf("expected in-progress current transaction, got %+v", current)
	}
	if !current.Interrupted() {
		t.Error("expected an in-progress transaction to be Interrupted()")
	}

	if err := journal.Complete(txn); err != nil {
		t.Fatal(err)
	}

	current, err = journal.Current()
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != lifecycle.StatusCompleted {
		t.Errorf("expected completed status, got %s", current.Status)
	}
	if current.CompletedAt == nil {
		t.Error("expected CompletedAt to be set")
	}
	if current.Interrupted() {
		t.Error("expected a completed transaction not to be Interrupted()")
	}
}

// Failure injection: a process that dies mid-operation leaves the
// journal's last transaction in-progress. A later invocation reading that
// same journal must be able to detect this.
func TestJournal_DetectsInterruptedOperation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transaction.json")

	crashed := lifecycle.NewJournal(path, false)
	if _, err := crashed.Begin("upgrade", "2.4.0", "2.5.0"); err != nil {
		t.Fatal(err)
	}
	// Simulates the process dying here, before Complete/Fail/RollBack.

	resumed := lifecycle.NewJournal(path, false)
	current, err := resumed.Current()
	if err != nil {
		t.Fatal(err)
	}
	if current == nil || !current.Interrupted() {
		t.Fatalf("expected the next invocation to observe an interrupted transaction, got %+v", current)
	}
	if current.Type != "upgrade" || current.SourceVersion != "2.4.0" || current.TargetVersion != "2.5.0" {
		t.Errorf("expected interrupted transaction details to be preserved, got %+v", current)
	}
}

func TestJournal_DryRunDoesNotPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transaction.json")

	dryRun := lifecycle.NewJournal(path, true)
	txn, err := dryRun.Begin("install", "", "2.4.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := dryRun.Complete(txn); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected dry-run to leave no journal file on disk, stat err=%v", err)
	}

	// A dry-run journal must still surface the *real* current state if one
	// already exists, so a dry-run install correctly reports an
	// interrupted prior operation instead of hiding it.
	real := lifecycle.NewJournal(path, false)
	realTxn, err := real.Begin("install", "", "2.4.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := real.Complete(realTxn); err != nil {
		t.Fatal(err)
	}

	dryRun2 := lifecycle.NewJournal(path, true)
	current, err := dryRun2.Current()
	if err != nil {
		t.Fatal(err)
	}
	if current == nil || current.ID != realTxn.ID {
		t.Errorf("expected dry-run Current() to see the real persisted transaction, got %+v", current)
	}
}

// Failure injection: a write that cannot complete (here, a read-only
// journal directory) must not corrupt or lose the previously persisted
// transaction.
func TestJournal_FailedWriteLeavesPriorStateIntact(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses the permission check this test relies on")
	}

	dir := t.TempDir()
	journalDir := filepath.Join(dir, "state")
	path := filepath.Join(journalDir, "transaction.json")

	journal := lifecycle.NewJournal(path, false)
	txn, err := journal.Begin("install", "", "2.4.0")
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(journalDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(journalDir, 0o750) })

	if err := journal.Complete(txn); err == nil {
		t.Fatal("expected Complete to fail while the journal directory is read-only")
	}

	if err := os.Chmod(journalDir, 0o750); err != nil {
		t.Fatal(err)
	}

	current, err := journal.Current()
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != lifecycle.StatusInProgress {
		t.Errorf("expected the prior in-progress transaction to survive the failed write, got status %s", current.Status)
	}
	if current.ID != txn.ID {
		t.Errorf("expected the same transaction ID to survive, got %s want %s", current.ID, txn.ID)
	}
}
