package recoveryset

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKubernetesPostgresExporterStreamsCustomDump(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database.dump")
	var got []string
	e := KubernetesPostgresExporter{Kubeconfig: "/kube", Namespace: "ace-infra", StatefulSet: "controlplane-database", Image: "registry.local/postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Stream: func(_ context.Context, destination, name string, args ...string) error {
		if name != "kubectl" || destination != path {
			t.Fatalf("stream target %q %q", name, destination)
		}
		got = args
		return os.WriteFile(destination, []byte("dump"), 0o600)
	}}
	artifact, err := e.Export(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, " ")
	for _, want := range []string{"exec statefulset/controlplane-database", "-c postgres", "pg_dump --format=custom"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("command %q missing %q", joined, want)
		}
	}
	if strings.Contains(joined, "POSTGRES_PASSWORD") {
		t.Fatalf("password must not appear in host command: %q", joined)
	}
	if artifact.Engine != "postgres" || artifact.Format != "custom" || len(artifact.SHA256) != 64 {
		t.Fatalf("artifact %#v", artifact)
	}
}
