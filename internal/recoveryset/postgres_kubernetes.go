package recoveryset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
)

// KubernetesPostgresExporter runs pg_dump inside the database container, so
// credentials remain Kubernetes Secret-backed environment variables and never
// cross the host command line. Its stdout is streamed to the protected path.
type KubernetesPostgresExporter struct {
	Kubeconfig, Namespace, StatefulSet string
	Image                              string
	Stream                             func(context.Context, string, string, ...string) error
	Run                                cli.Runner
}

func (e KubernetesPostgresExporter) Export(ctx context.Context, destination string) (DatabaseArtifact, error) {
	if e.Stream == nil {
		e.Stream = cli.ExecToFile
	}
	if e.Kubeconfig == "" || e.Namespace == "" || e.StatefulSet == "" || !strings.HasPrefix(e.Image, "registry.local/postgres@sha256:") {
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

func (e KubernetesPostgresExporter) VerifyRestore(ctx context.Context, artifact DatabaseArtifact) error {
	return e.verifyRestore(ctx, artifact)
}

func (e KubernetesPostgresExporter) verifyRestore(ctx context.Context, artifact DatabaseArtifact) error {
	if e.Run == nil {
		e.Run = cli.Exec
	}
	if e.Kubeconfig == "" || e.Namespace == "" || !strings.HasPrefix(e.Image, "registry.local/postgres@sha256:") {
		return fmt.Errorf("recovery set: Kubernetes PostgreSQL verifier is incomplete")
	}
	if artifact.Engine != "postgres" || artifact.Format != "custom" || artifact.Path == "" || len(artifact.SHA256) < 12 {
		return fmt.Errorf("recovery set: unsupported database artifact")
	}
	name := "recovery-verify-" + artifact.SHA256[:12]
	base := []string{"--kubeconfig", e.Kubeconfig, "--namespace", e.Namespace}
	if _, err := e.Run(ctx, "kubectl", append(base, "run", name, "--image="+e.Image, "--restart=Never", "--env=POSTGRES_HOST_AUTH_METHOD=trust", "--command", "--", "postgres")...); err != nil {
		return fmt.Errorf("recovery set: create isolated PostgreSQL verifier: %w", err)
	}
	defer func() {
		_, _ = e.Run(context.Background(), "kubectl", append(base, "delete", "pod", name, "--ignore-not-found")...)
	}()
	waitCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if _, err := e.Run(waitCtx, "kubectl", append(base, "wait", "--for=condition=Ready", "pod/"+name, "--timeout=90s")...); err != nil {
		return fmt.Errorf("recovery set: wait for isolated PostgreSQL verifier: %w", err)
	}
	if _, err := e.Run(ctx, "kubectl", append(base, "cp", artifact.Path, name+":/tmp/database.dump", "-c", "postgres")...); err != nil {
		return fmt.Errorf("recovery set: copy logical dump to verifier: %w", err)
	}
	if _, err := e.Run(ctx, "kubectl", append(base, "exec", name, "-c", "postgres", "--", "sh", "-ec", "pg_restore --list /tmp/database.dump >/dev/null && pg_restore --no-owner --no-acl -U postgres -d postgres /tmp/database.dump")...); err != nil {
		return fmt.Errorf("recovery set: restore logical dump in verifier: %w", err)
	}
	return nil
}
