// Package verify implements the release pipeline's fail-closed
// verification policy: digest, signature, provenance identity, and
// vulnerability-exception checks that gate intake and installation. Every
// function here fails closed — a missing file, mismatch, or expired
// exception is an error, never a silent pass.
package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// Digest computes the file's SHA-256 digest in the "sha256:<hex>" form
// used throughout the release schemas.
func Digest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("verify: open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("verify: read %s: %w", path, err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyDigest fails closed: a missing file, read error, or digest
// mismatch are all reported as an error.
func VerifyDigest(path, expected string) error {
	actual, err := Digest(path)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("verify: digest mismatch for %s: expected %s, got %s", path, expected, actual)
	}
	return nil
}

// VerifySize fails closed on a missing file or a size mismatch.
func VerifySize(path string, expected int64) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("verify: stat %s: %w", path, err)
	}
	if info.Size() != expected {
		return fmt.Errorf("verify: size mismatch for %s: expected %d bytes, got %d", path, expected, info.Size())
	}
	return nil
}
