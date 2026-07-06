package lifecycle

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// OperationStatus mirrors installed-state.v1.schema.json's operation
// status enum.
type OperationStatus string

const (
	StatusInProgress OperationStatus = "in-progress"
	StatusCompleted  OperationStatus = "completed"
	StatusFailed     OperationStatus = "failed"
	StatusRolledBack OperationStatus = "rolled-back"
)

// Transaction records one lifecycle operation (install, upgrade, backup,
// restore, repair, uninstall, factory-reset) from start to finish.
type Transaction struct {
	ID            string          `json:"transactionId"`
	Type          string          `json:"type"`
	Status        OperationStatus `json:"status"`
	StartedAt     time.Time       `json:"startedAt"`
	CompletedAt   *time.Time      `json:"completedAt,omitempty"`
	SourceVersion string          `json:"sourceVersion,omitempty"`
	TargetVersion string          `json:"targetVersion,omitempty"`
}

// Interrupted reports whether this transaction never reached a terminal
// status, meaning the process that started it died or was killed
// mid-operation.
func (t *Transaction) Interrupted() bool {
	return t.Status == StatusInProgress
}

// Journal is the atomically-written, single-record transaction journal
// backing "Create protected appliance directories and an atomic
// installed-state journal" (Fresh Install Sequence step 5). Reading
// Current() before starting a new operation is how the CLI detects an
// interrupted prior operation.
type Journal struct {
	path   string
	dryRun bool
}

// NewJournal returns a Journal backed by path. When dryRun is true,
// Begin/Complete/Fail/RollBack never write to disk, so a dry-run
// invocation cannot leave behind or corrupt real journal state.
func NewJournal(path string, dryRun bool) *Journal {
	return &Journal{path: path, dryRun: dryRun}
}

// Current returns the last recorded transaction, or nil if the journal
// has never been written (a fresh host).
func (j *Journal) Current() (*Transaction, error) {
	data, err := os.ReadFile(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lifecycle: read journal %s: %w", j.path, err)
	}

	var txn Transaction
	if err := json.Unmarshal(data, &txn); err != nil {
		return nil, fmt.Errorf("lifecycle: parse journal %s: %w", j.path, err)
	}
	return &txn, nil
}

// Begin starts a new transaction and persists it as in-progress before
// returning, so a crash immediately after Begin is still visible to the
// next Current() call.
func (j *Journal) Begin(operation, sourceVersion, targetVersion string) (*Transaction, error) {
	txn := &Transaction{
		ID:            newTransactionID(),
		Type:          operation,
		Status:        StatusInProgress,
		StartedAt:     time.Now().UTC(),
		SourceVersion: sourceVersion,
		TargetVersion: targetVersion,
	}
	if err := j.persist(txn); err != nil {
		return nil, err
	}
	return txn, nil
}

// Complete, Fail, and RollBack move a transaction to its terminal status
// and persist it.
func (j *Journal) Complete(txn *Transaction) error { return j.finish(txn, StatusCompleted) }
func (j *Journal) Fail(txn *Transaction) error     { return j.finish(txn, StatusFailed) }
func (j *Journal) RollBack(txn *Transaction) error { return j.finish(txn, StatusRolledBack) }

func (j *Journal) finish(txn *Transaction, status OperationStatus) error {
	txn.Status = status
	now := time.Now().UTC()
	txn.CompletedAt = &now
	return j.persist(txn)
}

func (j *Journal) persist(txn *Transaction) error {
	if j.dryRun {
		return nil
	}

	data, err := json.MarshalIndent(txn, "", "  ")
	if err != nil {
		return fmt.Errorf("lifecycle: marshal transaction: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(j.path), 0o750); err != nil {
		return fmt.Errorf("lifecycle: create journal directory: %w", err)
	}
	return WriteFileAtomic(j.path, data, 0o640)
}

func newTransactionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "txn-" + hex.EncodeToString(b[:])
}
