package helm_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/helm"
)

func TestDatabaseConnectionReplicaReplacesStalePassword(t *testing.T) {
	sourcePassword := base64.StdEncoding.EncodeToString([]byte("new-password"))
	sourceDSN := base64.StdEncoding.EncodeToString([]byte("postgresql://controlplane:new-password@db:5432/controlplane"))
	targetPassword := base64.StdEncoding.EncodeToString([]byte("old-password"))
	targetDSN := base64.StdEncoding.EncodeToString([]byte("postgresql://controlplane:old-password@db:5432/controlplane"))
	var patched string
	deleted := false

	run := func(_ context.Context, name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(call, "get namespace"):
			return "Active", nil
		case strings.Contains(call, "--namespace ace-infra") && strings.Contains(call, "get secret"):
			payload, _ := json.Marshal(map[string]any{"data": map[string]string{"password": sourcePassword, "dsn": sourceDSN}})
			return string(payload), nil
		case strings.Contains(call, "--namespace ace-system") && strings.Contains(call, "get secret"):
			payload, _ := json.Marshal(map[string]any{"data": map[string]string{"password": targetPassword, "dsn": targetDSN}})
			return string(payload), nil
		case strings.Contains(call, "patch secret controlplane-database-connection"):
			for i, arg := range args {
				if arg == "-p" && i+1 < len(args) {
					patched = args[i+1]
				}
			}
			return "", nil
		case strings.Contains(call, "delete secret controlplane-database-connection"):
			deleted = true
			return "", nil
		default:
			return "", fmt.Errorf("unexpected call: %s", call)
		}
	}

	prepared, err := helm.EnsureControlPlaneDatabaseConnectionReplica(context.Background(), run, "/kubeconfig", "ace-infra", "ace-system", "controlplane-database-connection")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(patched, sourcePassword) || strings.Contains(patched, targetPassword) {
		t.Fatalf("stale replica was not replaced from the infrastructure secret: %s", patched)
	}
	if err := prepared.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("rollback left the replaced database connection replica in place")
	}
}

func TestDatabaseConnectionReplicaKeepsMatchingSecret(t *testing.T) {
	password := base64.StdEncoding.EncodeToString([]byte("same-password"))
	dsn := base64.StdEncoding.EncodeToString([]byte("postgresql://controlplane:same-password@db:5432/controlplane"))
	payload, _ := json.Marshal(map[string]any{"data": map[string]string{"password": password, "dsn": dsn}})

	run := func(_ context.Context, name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(call, "get namespace"):
			return "Active", nil
		case strings.Contains(call, "get secret"):
			return string(payload), nil
		default:
			return "", fmt.Errorf("unexpected call: %s", call)
		}
	}

	if _, err := helm.EnsureControlPlaneDatabaseConnectionReplica(context.Background(), run, "/kubeconfig", "ace-infra", "ace-system", "controlplane-database-connection"); err != nil {
		t.Fatal(err)
	}
}
