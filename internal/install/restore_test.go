package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestoreBootstrapPostgresCopiesThenRestores(t *testing.T) {
	dump := filepath.Join(t.TempDir(), "database.dump")
	if err := os.WriteFile(dump, []byte("dump"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	err := restoreBootstrapPostgres(context.Background(), func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "", nil
	}, "/kube", "ace-infra", dump)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "cp "+dump+" controlplane-database-0:/tmp/recovery-set.dump -c postgres") || !strings.Contains(joined, "pg_restore --no-owner --no-acl") {
		t.Fatalf("expected protected copy and restore, got:\n%s", joined)
	}
}

func TestRestoreBootstrapPostgresRefusesMissingArtifact(t *testing.T) {
	if err := restoreBootstrapPostgres(context.Background(), nil, "/kube", "ace-infra", filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing artifact accepted")
	}
}
