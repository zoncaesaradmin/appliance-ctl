package recoveryset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
)

// KubernetesPostgresExporter runs pg_dump inside the database container, so
// credentials remain Kubernetes Secret-backed environment variables and never
// cross the host command line. Its stdout is streamed to the protected path.
type KubernetesPostgresExporter struct {
	Kubeconfig, Namespace, StatefulSet string
	Stream                             func(context.Context, string, string, ...string) error
}

func (e KubernetesPostgresExporter) Export(ctx context.Context, destination string) (DatabaseArtifact, error) {
	if e.Stream == nil {
		e.Stream = cli.ExecToFile
	}
	if e.Kubeconfig == "" || e.Namespace == "" || e.StatefulSet == "" {
		return DatabaseArtifact{}, fmt.Errorf("recovery set: Kubernetes PostgreSQL exporter is incomplete")
	}
	args := []string{"--kubeconfig", e.Kubeconfig, "--namespace", e.Namespace, "exec", "statefulset/" + e.StatefulSet, "-c", "postgres", "--", "sh", "-ec", "exec pg_dump --format=custom --no-owner --no-acl -U \"$POSTGRES_USER\" \"$POSTGRES_DB\""}
	if err := e.Stream(ctx, destination, "kubectl", args...); err != nil {
		return DatabaseArtifact{}, fmt.Errorf("recovery set: pg_dump: %w", err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		return DatabaseArtifact{}, err
	}
	sum := sha256.Sum256(data)
	return DatabaseArtifact{Engine: "postgres", Format: "custom", Path: destination, SHA256: hex.EncodeToString(sum[:])}, nil
}

func (e KubernetesPostgresExporter) VerifyRestore(context.Context, DatabaseArtifact) error {
	return fmt.Errorf("recovery set: isolated PostgreSQL restore verifier is not configured")
}
