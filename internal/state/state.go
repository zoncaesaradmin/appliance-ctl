// Package state persists the installed-state.v1 record: the atomic,
// signed-schema-conformant journal of exactly what is installed, used by
// status, verify, upgrade compatibility checks, and K3s ownership
// decisions.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/lifecycle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/manifest"
)

// Components records the installed version of every product component
// this appliance version owns.
type Components struct {
	K3sVersion   string `json:"k3sVersion"`
	ChartVersion string `json:"chartVersion"`
	ZotVersion   string `json:"zotVersion,omitempty"`
}

// K3sOwnership records that the installed K3s belongs to this appliance
// installation. Per "K3s Ownership" in docs/release-plan.md, an unrelated
// pre-existing cluster is never accepted in v1, so Owned is always true
// for any state this package will persist.
type K3sOwnership struct {
	Owned                 bool   `json:"owned"`
	OwnerApplianceVersion string `json:"ownerApplianceVersion"`
}

// Operation is one lifecycle transaction recorded in InstalledState's
// history, mirroring lifecycle.Transaction's terminal shape.
type Operation struct {
	Type          string     `json:"type"`
	Status        string     `json:"status"`
	TransactionID string     `json:"transactionId"`
	StartedAt     time.Time  `json:"startedAt"`
	CompletedAt   *time.Time `json:"completedAt,omitempty"`
	SourceVersion string     `json:"sourceVersion,omitempty"`
	TargetVersion string     `json:"targetVersion,omitempty"`
}

// InstalledState is the on-host record of exactly what is installed,
// matching schemas/installed-state.v1.schema.json.
type InstalledState struct {
	SchemaVersion       int          `json:"schemaVersion"`
	ApplianceInstanceID string       `json:"applianceInstanceId"`
	InstalledVersion    string       `json:"installedVersion"`
	InstalledReleaseID  string       `json:"installedReleaseId"`
	ApplianceProfile    string       `json:"applianceProfile,omitempty"`
	Components          Components   `json:"components"`
	K3sOwnership        K3sOwnership `json:"k3sOwnership"`
	LastOperation       Operation    `json:"lastOperation"`
	History             []Operation  `json:"history,omitempty"`
	CreatedAt           time.Time    `json:"createdAt"`
	UpdatedAt           time.Time    `json:"updatedAt"`
}

// Load reads and schema-validates the installed-state record at path. It
// returns (nil, nil) when the file does not exist, meaning a fresh host
// with no prior installation.
func Load(path string) (*InstalledState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("state: read %s: %w", path, err)
	}

	if err := manifest.Validate(manifest.KindInstalledState, data); err != nil {
		return nil, fmt.Errorf("state: %s does not satisfy installed-state.v1: %w", path, err)
	}

	var s InstalledState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("state: parse %s: %w", path, err)
	}
	return &s, nil
}

// Save schema-validates s and writes it atomically to path.
func Save(path string, s *InstalledState) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("state: marshal installed state: %w", err)
	}

	if err := manifest.Validate(manifest.KindInstalledState, data); err != nil {
		return fmt.Errorf("state: assembled installed state failed schema validation: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("state: create directory for %s: %w", path, err)
	}
	return lifecycle.WriteFileAtomic(path, data, 0o640)
}
