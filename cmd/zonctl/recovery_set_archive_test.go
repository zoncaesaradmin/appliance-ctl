package main

import (
	"archive/tar"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
)

func TestArchiveDirectoryWritesRelativeRegularFiles(t *testing.T) {
	source := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "object"), []byte("blob"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "blob-storage.tar")
	if err := archiveDirectory(source, archive); err != nil {
		t.Fatalf("archiveDirectory: %v", err)
	}
	in, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	r := tar.NewReader(in)
	seen := false
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == "nested/object" {
			data, err := io.ReadAll(r)
			if err != nil || string(data) != "blob" {
				t.Fatalf("entry = %q, %v", data, err)
			}
			seen = true
		}
	}
	if !seen {
		t.Fatal("blob object was not archived")
	}
}

func TestArchiveQuiescedBlobStorageRestoresAvailability(t *testing.T) {
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "object"), []byte("blob"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	run := cli.Runner(func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if strings.Contains(strings.Join(args, " "), "jsonpath={.spec.replicas}") {
			return "1", nil
		}
		return "", nil
	})
	if err := archiveQuiescedBlobStorage(context.Background(), run, source, filepath.Join(t.TempDir(), "blobs.tar")); err != nil {
		t.Fatalf("archiveQuiescedBlobStorage: %v", err)
	}
	joined := strings.Join(calls, "\n")
	for _, required := range []string{
		"scale deployment blob-storage --replicas=0",
		"wait --for=delete pod --selector=app.kubernetes.io/name=blob-storage --timeout=120s",
		"scale deployment blob-storage --replicas=1",
		"rollout status deployment/blob-storage --timeout=120s",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("missing %q in calls:\n%s", required, joined)
		}
	}
}

func TestArchiveQuiescedBlobStorageRestoresAvailabilityAfterArchiveFailure(t *testing.T) {
	var calls []string
	run := cli.Runner(func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if strings.Contains(strings.Join(args, " "), "jsonpath={.spec.replicas}") {
			return "1", nil
		}
		return "", nil
	})
	err := archiveQuiescedBlobStorage(context.Background(), run, filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "blobs.tar"))
	if err == nil {
		t.Fatal("expected archive failure")
	}
	if !strings.Contains(strings.Join(calls, "\n"), "scale deployment blob-storage --replicas=1") {
		t.Fatalf("blob-storage was not restored after failure: %v", calls)
	}
}
