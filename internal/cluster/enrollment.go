// Package cluster owns cluster-scoped enrollment artifacts. It deliberately
// contains no network discovery: a worker joins only from an operator supplied
// enrollment file that is signed by the existing appliance control plane.
package cluster

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/lifecycle"
)

const EnrollmentVersion = 1

// Enrollment is a short-lived, single-worker K3s join authorization. The
// token is intentionally absent from installed-state and command arguments;
// it is carried only in this protected file and copied into an agent-only
// token file during the join transaction.
type Enrollment struct {
	Version          int       `json:"version"`
	ClusterID        string    `json:"clusterId"`
	ApplianceName    string    `json:"applianceName"`
	ApplianceProfile string    `json:"applianceProfile"`
	ControlPlaneNode string    `json:"controlPlaneNode"`
	NodeRole         string    `json:"nodeRole"`
	ReleaseID        string    `json:"releaseId"`
	ReleaseVersion   string    `json:"releaseVersion"`
	ControlEndpoint  string    `json:"controlEndpoint"`
	ClusterCAHash    string    `json:"clusterCAHash"`
	ExpectedNodeName string    `json:"expectedNodeName"`
	K3sToken         string    `json:"k3sToken"`
	TokenFingerprint string    `json:"tokenFingerprint"`
	IssuedAt         time.Time `json:"issuedAt"`
	ExpiresAt        time.Time `json:"expiresAt"`
	Nonce            string    `json:"nonce"`
	SignerPublicKey  string    `json:"signerPublicKey"`
	Signature        string    `json:"signature"`
}

type unsignedEnrollment Enrollment

func (e Enrollment) unsigned() unsignedEnrollment {
	e.Signature = ""
	return unsignedEnrollment(e)
}

// Sign signs e in place using the cluster enrollment private key.
func (e *Enrollment) Sign(private ed25519.PrivateKey) error {
	if len(private) != ed25519.PrivateKeySize {
		return errors.New("cluster enrollment: invalid private key")
	}
	e.Version = EnrollmentVersion
	e.SignerPublicKey = base64.RawStdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	payload, err := json.Marshal(e.unsigned())
	if err != nil {
		return fmt.Errorf("cluster enrollment: marshal: %w", err)
	}
	e.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, payload))
	return nil
}

// Validate verifies the artifact before any worker host mutation. expectedKey
// is the public-key fingerprint obtained through the trusted cluster record;
// accepting the public key embedded in the artifact alone would permit an
// attacker to replace both it and the signature.
func (e Enrollment) Validate(now time.Time, expectedKey string) error {
	if e.Version != EnrollmentVersion {
		return fmt.Errorf("cluster enrollment: unsupported version %d", e.Version)
	}
	for field, value := range map[string]string{
		"clusterId": e.ClusterID, "applianceName": e.ApplianceName, "applianceProfile": e.ApplianceProfile,
		"controlPlaneNode": e.ControlPlaneNode, "nodeRole": e.NodeRole,
		"releaseId": e.ReleaseID, "releaseVersion": e.ReleaseVersion, "controlEndpoint": e.ControlEndpoint,
		"clusterCAHash": e.ClusterCAHash, "expectedNodeName": e.ExpectedNodeName,
		"k3sToken": e.K3sToken, "tokenFingerprint": e.TokenFingerprint, "nonce": e.Nonce,
		"signerPublicKey": e.SignerPublicKey, "signature": e.Signature,
	} {
		if value == "" {
			return fmt.Errorf("cluster enrollment: %s is required", field)
		}
	}
	if !e.ExpiresAt.After(now.UTC()) || e.IssuedAt.After(now.UTC().Add(5*time.Minute)) {
		return errors.New("cluster enrollment: expired or not yet valid")
	}
	if e.ExpiresAt.Sub(e.IssuedAt) > 24*time.Hour {
		return errors.New("cluster enrollment: validity must not exceed 24 hours")
	}
	if e.NodeRole != "worker" && e.NodeRole != "inference" && e.NodeRole != "prime" {
		return errors.New("cluster enrollment: node role must be worker, inference, or prime")
	}
	if len(e.ClusterCAHash) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(e.ClusterCAHash, "sha256:") {
		return errors.New("cluster enrollment: invalid cluster CA hash")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(e.ClusterCAHash, "sha256:")); err != nil {
		return errors.New("cluster enrollment: invalid cluster CA hash")
	}
	endpoint, err := url.Parse(e.ControlEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return errors.New("cluster enrollment: control endpoint must be an https URL")
	}
	if TokenFingerprint(e.K3sToken) != e.TokenFingerprint {
		return errors.New("cluster enrollment: token fingerprint mismatch")
	}
	public, err := base64.RawStdEncoding.DecodeString(e.SignerPublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return errors.New("cluster enrollment: invalid signer public key")
	}
	if strings.TrimSpace(expectedKey) == "" {
		return errors.New("cluster enrollment: expected signer fingerprint is required")
	}
	if Fingerprint(ed25519.PublicKey(public)) != expectedKey {
		return errors.New("cluster enrollment: unexpected signer public key")
	}
	signature, err := base64.RawStdEncoding.DecodeString(e.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("cluster enrollment: invalid signature")
	}
	payload, err := json.Marshal(e.unsigned())
	if err != nil {
		return fmt.Errorf("cluster enrollment: marshal verification payload: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(public), payload, signature) {
		return errors.New("cluster enrollment: signature verification failed")
	}
	return nil
}

// WriteEnrollment writes an enrollment artifact owner-readable only. The
// caller supplies a deliberate output path because the artifact contains the
// K3s join credential and must not be printed or written into state.
func WriteEnrollment(path string, enrollment Enrollment) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("cluster enrollment: output path is required")
	}
	data, err := json.Marshal(enrollment)
	if err != nil {
		return fmt.Errorf("cluster enrollment: marshal file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("cluster enrollment: create output directory: %w", err)
	}
	if err := lifecycle.WriteFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("cluster enrollment: write output: %w", err)
	}
	return nil
}

// ReadEnrollment parses an artifact without logging its contents.
func ReadEnrollment(path string) (Enrollment, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Enrollment{}, fmt.Errorf("cluster enrollment: read artifact: %w", err)
	}
	var enrollment Enrollment
	if err := json.Unmarshal(data, &enrollment); err != nil {
		return Enrollment{}, fmt.Errorf("cluster enrollment: parse artifact: %w", err)
	}
	return enrollment, nil
}

func TokenFingerprint(token string) string        { return hashString(token) }
func Fingerprint(public ed25519.PublicKey) string { return hashBytes(public) }

func hashString(value string) string { return hashBytes([]byte(value)) }
func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// NewNonce returns a URL-safe random nonce for a one-worker artifact.
func NewNonce() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
