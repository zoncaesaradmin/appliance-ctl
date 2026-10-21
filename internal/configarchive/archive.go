// Package configarchive owns the portable, encrypted configuration archive
// envelope used by zonctl. It has no database or appliance-local dependency:
// the same file works for a local PostgreSQL appliance and a cloud-managed
// PostgreSQL deployment because import always goes through the control-plane
// configuration API.
package configarchive

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

const Format = "configuration-archive.zon/v1"

type Manifest struct {
	Format        string    `json:"format"`
	ArchiveID     string    `json:"archiveId"`
	CreatedAt     time.Time `json:"createdAt"`
	RevisionID    string    `json:"revisionId"`
	SchemaVersion string    `json:"schemaVersion"`
	PayloadDigest string    `json:"payloadDigest"`
	KeyID         string    `json:"keyId"`
}

type envelope struct {
	Manifest   Manifest `json:"manifest"`
	Nonce      []byte   `json:"nonce"`
	Ciphertext []byte   `json:"ciphertext"`
}

// Seal creates an authenticated portable archive. key is supplied only by a
// protected operator file and is never written to the archive or command
// output.
func Seal(revisionID, schemaVersion string, payload []byte, key []byte) ([]byte, Manifest, error) {
	if len(key) != 32 {
		return nil, Manifest{}, fmt.Errorf("configuration archive key must be exactly 32 bytes")
	}
	if revisionID == "" || schemaVersion == "" || len(payload) == 0 {
		return nil, Manifest{}, fmt.Errorf("configuration revision identity, schema, and payload are required")
	}
	sum := sha256.Sum256(payload)
	keySum := sha256.Sum256(key)
	manifest := Manifest{
		Format: Format, ArchiveID: archiveID(), CreatedAt: time.Now().UTC(), RevisionID: revisionID,
		SchemaVersion: schemaVersion, PayloadDigest: "sha256:" + hex.EncodeToString(sum[:]),
		KeyID: hex.EncodeToString(keySum[:8]),
	}
	additionalData, err := json.Marshal(manifest)
	if err != nil {
		return nil, Manifest{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, Manifest{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, Manifest{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, Manifest{}, fmt.Errorf("generate archive nonce: %w", err)
	}
	data, err := json.Marshal(envelope{Manifest: manifest, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, payload, additionalData)})
	if err != nil {
		return nil, Manifest{}, err
	}
	return data, manifest, nil
}

// Open authenticates an archive and returns its portable configuration
// payload. The caller submits it to the target's clean-target import API.
func Open(data, key []byte) (Manifest, []byte, error) {
	if len(key) != 32 {
		return Manifest{}, nil, fmt.Errorf("configuration archive key must be exactly 32 bytes")
	}
	var value envelope
	if err := json.Unmarshal(data, &value); err != nil {
		return Manifest{}, nil, fmt.Errorf("decode configuration archive: %w", err)
	}
	if value.Manifest.Format != Format || value.Manifest.ArchiveID == "" || value.Manifest.RevisionID == "" || value.Manifest.SchemaVersion == "" || value.Manifest.PayloadDigest == "" {
		return Manifest{}, nil, fmt.Errorf("unsupported or incomplete configuration archive manifest")
	}
	keySum := sha256.Sum256(key)
	if value.Manifest.KeyID != hex.EncodeToString(keySum[:8]) {
		return Manifest{}, nil, fmt.Errorf("configuration archive key identifier does not match")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Manifest{}, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(value.Nonce) != aead.NonceSize() {
		return Manifest{}, nil, fmt.Errorf("invalid configuration archive nonce")
	}
	additionalData, err := json.Marshal(value.Manifest)
	if err != nil {
		return Manifest{}, nil, err
	}
	payload, err := aead.Open(nil, value.Nonce, value.Ciphertext, additionalData)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("configuration archive authentication failed: %w", err)
	}
	sum := sha256.Sum256(payload)
	if value.Manifest.PayloadDigest != "sha256:"+hex.EncodeToString(sum[:]) {
		return Manifest{}, nil, fmt.Errorf("configuration archive payload digest does not match")
	}
	return value.Manifest, payload, nil
}

func archiveID() string {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UTC().UnixNano())))
		return "archive-" + hex.EncodeToString(sum[:16])
	}
	return "archive-" + hex.EncodeToString(value[:])
}
