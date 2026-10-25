package clustertopology

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/lifecycle"
)

const (
	BootstrapStateVersion = 1
	PhasePrepared         = "prepared"
	PhaseServerReady      = "server-ready"
	PhaseJoined           = "joined"
	PhaseFinalized        = "finalized"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// BootstrapState is a local, non-secret receipt for the unfinished substrate.
// It is never an InstalledState: one or two etcd members and a K3s server
// without product charts are not a completed appliance installation.
type BootstrapState struct {
	SchemaVersion               int       `json:"schemaVersion"`
	Topology                    string    `json:"topology"`
	InventoryFingerprint        string    `json:"inventoryFingerprint"`
	ClusterID                   string    `json:"clusterId"`
	ApplianceName               string    `json:"applianceName"`
	ApplianceProfile            string    `json:"applianceProfile"`
	DNSZone                     string    `json:"dnsZone"`
	ReleaseID                   string    `json:"releaseId"`
	BundleVersion               string    `json:"bundleVersion"`
	K3sVersion                  string    `json:"k3sVersion"`
	LocalNode                   string    `json:"localNode"`
	Phase                       string    `json:"phase"`
	NodeUID                     string    `json:"nodeUID,omitempty"`
	EnrollmentSignerFingerprint string    `json:"enrollmentSignerFingerprint,omitempty"`
	CreatedAt                   time.Time `json:"createdAt"`
	UpdatedAt                   time.Time `json:"updatedAt"`
}

func (s BootstrapState) Validate() error {
	if s.SchemaVersion != BootstrapStateVersion || s.Topology != EmbeddedEtcdV1 {
		return errors.New("cluster bootstrap state: unsupported schema or topology")
	}
	if !digestPattern.MatchString(s.InventoryFingerprint) {
		return errors.New("cluster bootstrap state: invalid inventory fingerprint")
	}
	for field, value := range map[string]string{"clusterId": s.ClusterID, "applianceName": s.ApplianceName, "applianceProfile": s.ApplianceProfile, "dnsZone": s.DNSZone, "releaseId": s.ReleaseID, "bundleVersion": s.BundleVersion, "k3sVersion": s.K3sVersion, "localNode": s.LocalNode} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("cluster bootstrap state: %s is required", field)
		}
	}
	if !nodeNamePattern.MatchString(s.LocalNode) {
		return errors.New("cluster bootstrap state: invalid local node name")
	}
	if s.EnrollmentSignerFingerprint != "" && !digestPattern.MatchString(s.EnrollmentSignerFingerprint) {
		return errors.New("cluster bootstrap state: invalid enrollment signer fingerprint")
	}
	switch s.Phase {
	case PhasePrepared, PhaseServerReady:
		if s.NodeUID != "" {
			return errors.New("cluster bootstrap state: unobserved node must not have a UID")
		}
	case PhaseJoined, PhaseFinalized:
		if strings.TrimSpace(s.NodeUID) == "" {
			return errors.New("cluster bootstrap state: observed node UID is required")
		}
	default:
		return fmt.Errorf("cluster bootstrap state: unknown phase %q", s.Phase)
	}
	if s.CreatedAt.IsZero() || s.UpdatedAt.IsZero() || s.UpdatedAt.Before(s.CreatedAt) {
		return errors.New("cluster bootstrap state: invalid timestamps")
	}
	return nil
}

func (s BootstrapState) Matches(in Inventory, releaseID, bundleVersion, k3sVersion, nodeName, applianceName, applianceProfile, dnsZone string) error {
	if err := s.Validate(); err != nil {
		return err
	}
	fingerprint, err := in.Fingerprint()
	if err != nil {
		return err
	}
	if s.InventoryFingerprint != fingerprint || s.ReleaseID != releaseID || s.BundleVersion != bundleVersion || s.K3sVersion != k3sVersion || s.LocalNode != nodeName || s.ApplianceName != applianceName || s.ApplianceProfile != applianceProfile || s.DNSZone != dnsZone {
		return errors.New("cluster bootstrap state: rerun inputs differ from the staged cluster; refuse to overwrite it")
	}
	return nil
}

// LoadBootstrapState returns nil for a fresh host. It rejects unknown fields
// and malformed states so a rerun cannot silently reinterpret prior work.
func LoadBootstrapState(path string) (*BootstrapState, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cluster bootstrap state: open: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxInventoryBytes {
		return nil, errors.New("cluster bootstrap state: file must be regular and at most 64 KiB")
	}
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var s BootstrapState
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("cluster bootstrap state: decode: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return nil, errors.New("cluster bootstrap state: trailing data")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("cluster bootstrap state: trailing data: %w", err)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

func SaveBootstrapState(path string, s BootstrapState) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if !filepath.IsAbs(path) {
		return errors.New("cluster bootstrap state: path must be absolute")
	}
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("cluster bootstrap state: encode: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("cluster bootstrap state: create directory: %w", err)
	}
	return lifecycle.WriteFileAtomic(path, data, 0o640)
}
