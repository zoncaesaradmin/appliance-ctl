// Package fetch downloads and verifies remote artifacts when release
// engineering or future non-v1 workflows need controlled network
// acquisition. No normal v1 lifecycle command should rely on public
// network access.
package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// Getter fetches url and returns its body. The real implementation is
// HTTPGet; tests inject a fake so no test in this repository needs
// actual network access.
type Getter func(ctx context.Context, url string) ([]byte, error)

// HTTPGet is the real Getter, using the standard library HTTP client.
func HTTPGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch: build request for %s: %w", url, err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: get %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch: get %s: unexpected status %s", url, resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("fetch: read body from %s: %w", url, err)
	}
	return data, nil
}

// DownloadVerified fetches url via get, verifies its SHA-256 digest
// matches expectedDigest ("sha256:<hex>"), and only then writes it
// atomically to destPath. A digest mismatch never reaches destPath —
// this fails closed exactly like internal/verify does for offline
// bundle artifacts.
func DownloadVerified(ctx context.Context, get Getter, url, expectedDigest, destPath string, perm os.FileMode) error {
	data, err := get(ctx, url)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}

	sum := sha256.Sum256(data)
	actual := "sha256:" + hex.EncodeToString(sum[:])
	if actual != expectedDigest {
		return fmt.Errorf("fetch: %s digest mismatch: expected %s, got %s", url, expectedDigest, actual)
	}

	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("fetch: create directory for %s: %w", destPath, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-fetch-*")
	if err != nil {
		return fmt.Errorf("fetch: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("fetch: write %s: %w", destPath, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fetch: sync %s: %w", destPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("fetch: close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("fetch: chmod %s: %w", destPath, err)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("fetch: install %s: %w", destPath, err)
	}
	return nil
}
