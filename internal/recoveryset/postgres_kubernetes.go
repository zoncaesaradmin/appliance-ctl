package recoveryset

import (
	"context"
	"encoding/json"
	"fmt"
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
	Apply                              cli.InputRunner
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
	sum, err := ChecksumFile(destination)
	if err != nil {
		return DatabaseArtifact{}, fmt.Errorf("recovery set: checksum logical dump: %w", err)
	}
	return DatabaseArtifact{Engine: "postgres", Format: "custom", Path: destination, SHA256: sum}, nil
}

func (e KubernetesPostgresExporter) VerifyRestore(ctx context.Context, artifact DatabaseArtifact) error {
	return e.verifyRestore(ctx, artifact)
}

func (e KubernetesPostgresExporter) verifyRestore(ctx context.Context, artifact DatabaseArtifact) error {
	if e.Run == nil {
		e.Run = cli.Exec
	}
	if e.Apply == nil {
		e.Apply = cli.ExecInput
	}
	if e.Kubeconfig == "" || e.Namespace == "" || !strings.HasPrefix(e.Image, "registry.local/postgres@sha256:") {
		return fmt.Errorf("recovery set: Kubernetes PostgreSQL verifier is incomplete")
	}
	if artifact.Engine != "postgres" || artifact.Format != "custom" || artifact.Path == "" || len(artifact.SHA256) < 12 {
		return fmt.Errorf("recovery set: unsupported database artifact")
	}
	name := "recovery-verify-" + artifact.SHA256[:12]
	base := []string{"--kubeconfig", e.Kubeconfig, "--namespace", e.Namespace}
	manifest, err := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "labels": map[string]string{"app.kubernetes.io/name": "controlplane-database-recovery-verify"}},
		"spec": map[string]any{
			"restartPolicy": "Never", "automountServiceAccountToken": false,
			"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 70, "runAsGroup": 70, "fsGroup": 70, "fsGroupChangePolicy": "OnRootMismatch", "seccompProfile": map[string]string{"type": "RuntimeDefault"}},
			"containers": []any{map[string]any{
				"name": "postgres", "image": e.Image, "imagePullPolicy": "IfNotPresent", "args": []string{"postgres"},
				"env":             []map[string]string{{"name": "POSTGRES_HOST_AUTH_METHOD", "value": "trust"}},
				"securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string][]string{"drop": {"ALL"}}},
				"resources":       map[string]any{"requests": map[string]string{"cpu": "25m", "memory": "64Mi"}, "limits": map[string]string{"cpu": "250m", "memory": "256Mi"}},
				"volumeMounts":    []map[string]string{{"name": "data", "mountPath": "/var/lib/postgresql/data"}, {"name": "tmp", "mountPath": "/tmp"}, {"name": "run", "mountPath": "/var/run/postgresql"}},
			}},
			"volumes": []map[string]any{{"name": "data", "emptyDir": map[string]any{}}, {"name": "tmp", "emptyDir": map[string]any{}}, {"name": "run", "emptyDir": map[string]any{}}},
		},
	})
	if err != nil {
		return fmt.Errorf("recovery set: encode verifier pod: %w", err)
	}
	if _, err := e.Apply(ctx, manifest, "kubectl", append(base, "apply", "-f", "-")...); err != nil {
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
