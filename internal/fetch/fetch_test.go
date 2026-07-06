package fetch_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/fetch"
)

func digestOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fakeGetter(content string, err error) fetch.Getter {
	return func(context.Context, string) ([]byte, error) {
		return []byte(content), err
	}
}

func TestDownloadVerified_Success(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "k3s")
	content := "fake k3s binary bytes"

	err := fetch.DownloadVerified(context.Background(), fakeGetter(content, nil), "https://example.invalid/k3s", digestOf(content), dest, 0o755)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != content {
		t.Errorf("expected downloaded content to match, got %q", data)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("expected the requested executable permission, got mode %s", info.Mode())
	}
}

// Tamper/integrity: a digest mismatch must fail closed and never write
// the file to disk.
func TestDownloadVerified_DigestMismatchFailsClosed(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "k3s")

	err := fetch.DownloadVerified(context.Background(), fakeGetter("actual content", nil), "https://example.invalid/k3s",
		"sha256:0000000000000000000000000000000000000000000000000000000000000", dest, 0o755)
	if err == nil {
		t.Fatal("expected a digest mismatch to fail")
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Error("expected no file to be written when the digest does not match")
	}
}

func TestDownloadVerified_PropagatesGetterFailure(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "k3s")

	err := fetch.DownloadVerified(context.Background(), fakeGetter("", errors.New("connection refused")), "https://example.invalid/k3s",
		digestOf(""), dest, 0o755)
	if err == nil {
		t.Fatal("expected the getter failure to propagate")
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Error("expected no file to be written when the fetch itself fails")
	}
}
