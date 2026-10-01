package cluster

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// LoadOrCreateSigner persists the cluster-local enrollment signing key with
// owner-only permissions. The public fingerprint is recorded in cluster state;
// callers must never write the returned private key to state, logs, or output.
func LoadOrCreateSigner(path string) (ed25519.PrivateKey, string, error) {
	if data, err := os.ReadFile(path); err == nil {
		raw, decodeErr := base64.RawStdEncoding.DecodeString(string(data))
		if decodeErr != nil || len(raw) != ed25519.PrivateKeySize {
			return nil, "", errors.New("cluster enrollment: invalid private key file")
		}
		private := ed25519.PrivateKey(raw)
		return private, Fingerprint(private.Public().(ed25519.PublicKey)), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("cluster enrollment: read private key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, "", fmt.Errorf("cluster enrollment: create key directory: %w", err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("cluster enrollment: generate private key: %w", err)
	}
	encoded := []byte(base64.RawStdEncoding.EncodeToString(private))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return LoadOrCreateSigner(path)
		}
		return nil, "", fmt.Errorf("cluster enrollment: create private key: %w", err)
	}
	if _, err := f.Write(encoded); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, "", fmt.Errorf("cluster enrollment: write private key: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, "", fmt.Errorf("cluster enrollment: close private key: %w", err)
	}
	return private, Fingerprint(private.Public().(ed25519.PublicKey)), nil
}
