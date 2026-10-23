package main

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
	"testing"
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
