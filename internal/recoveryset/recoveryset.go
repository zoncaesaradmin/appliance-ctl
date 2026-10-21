// Package recoveryset defines the PostgreSQL-aware disaster-recovery boundary.
// It is intentionally separate from portable desired-configuration archives.
package recoveryset

import (
	"context"
	"errors"
	"fmt"
	"time"
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
	return nil
}
