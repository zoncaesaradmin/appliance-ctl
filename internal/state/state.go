// Package state persists the installed-state.v1 record: the atomic,
// signed-schema-conformant journal of exactly what is installed, used by
// status, verify, upgrade compatibility checks, and K3s ownership
// decisions.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zoncaesaradmin/appliance-ctl/internal/runtimeconfig"
	"os"
	"path/filepath"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/lifecycle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/manifest"
)

// Components records the installed version of every product component
// this appliance version owns.
type Components struct {
	K3sVersion            string `json:"k3sVersion"`
	ChartVersion          string `json:"chartVersion"`
	ArtifactServerVersion string `json:"artifactServerVersion,omitempty"`
	DNSVersion            string `json:"dnsVersion,omitempty"`
	InferenceVersion      string `json:"inferenceVersion,omitempty"`
	VideoVersion          string `json:"videoVersion,omitempty"`
	MetadataVersion       string `json:"metadataVersion,omitempty"`
	MetadataDigest        string `json:"metadataDigest,omitempty"`
}

// K3sOwnership records that the installed K3s belongs to this appliance
// installation. Per "K3s Ownership" in docs/release-plan.md, an unrelated
// pre-existing cluster is never accepted in v1, so Owned is always true
// for any state this package will persist.
type K3sOwnership struct {
	Owned                 bool   `json:"owned"`
	OwnerApplianceVersion string `json:"ownerApplianceVersion"`
}

// Cluster records the appliance-wide facts which must agree on every node.
// The installed-state file remains a local receipt in the initial topology,
// but these fields make the cluster boundary explicit rather than treating a
// host installation as the appliance identity. Join credentials deliberately
// do not belong here: they are short-lived secrets held in protected K3s
// configuration on the joining node.
type Cluster struct {
	ID               string `json:"id,omitempty"`
	Topology         string `json:"topology,omitempty"`
	ControlPlaneNode string `json:"controlPlaneNode,omitempty"`
	IngressNode      string `json:"ingressNode,omitempty"`
	// ControlEndpoint is the preferred K3s API URL used to join a live
	// server (usually the advertised prime). Every prime also serves the
	// same API on its own LAN IPv4:6443; see ControlEndpoints.
	ControlEndpoint string `json:"controlEndpoint,omitempty"`
	// ControlEndpoints lists every known prime API URL (https://<lan-ip>:6443).
	// There is no extra VIP. Clients may use any live entry.
	ControlEndpoints []string `json:"controlEndpoints,omitempty"`
	// ClusterCAHash pins the K3s server CA presented by ControlEndpoint. It is
	// public verification material, never a CA private key or join secret.
	ClusterCAHash string `json:"clusterCAHash,omitempty"`
	// EnrollmentSignerFingerprint pins the Ed25519 public key allowed to
	// authorize workers. It is public metadata and never contains the
	// private enrollment signer or a K3s join token.
	EnrollmentSignerFingerprint string        `json:"enrollmentSignerFingerprint,omitempty"`
	ClusterCIDR                 string        `json:"clusterCIDR,omitempty"`
	ServiceCIDR                 string        `json:"serviceCIDR,omitempty"`
	Nodes                       []ClusterNode `json:"nodes,omitempty"`
}

// ClusterNode is intentionally inventory, not a discovered peer. Nodes are
// enrolled through a trusted installer flow; mDNS must never add members.
type ClusterNode struct {
	ID      string   `json:"id"`
	NodeUID string   `json:"nodeUID,omitempty"`
	Name    string   `json:"name"`
	Role    string   `json:"role"`
	Roles   []string `json:"roles,omitempty"`
}

const (
	TopologySingleServer  = "single-server"
	TopologyServerWorkers = "server-workers"
	TopologyMultiServer   = "multi-server"
	NodeRoleControlPlane  = "control-plane"
	NodeRoleWorker        = "worker"
	NodeRoleInference     = "inference"
)

// NewSingleServerCluster constructs the v1-compatible cluster record. The
// appliance instance ID is also the cluster ID while one host is the complete
// cluster; future workers receive their own local receipt but share this ID.
func NewSingleServerCluster(id, nodeName, clusterCIDR, serviceCIDR string) Cluster {
	return Cluster{
		ID:               id,
		Topology:         TopologySingleServer,
		ControlPlaneNode: nodeName,
		IngressNode:      nodeName,
		ClusterCIDR:      clusterCIDR,
		ServiceCIDR:      serviceCIDR,
		Nodes: []ClusterNode{{
			ID:    nodeName,
			Name:  nodeName,
			Role:  NodeRoleControlPlane,
			Roles: []string{NodeRoleControlPlane},
		}},
	}
}

// Operation is one lifecycle transaction recorded in InstalledState's
// history, mirroring lifecycle.Transaction's terminal shape.
type Operation struct {
	Type          string     `json:"type"`
	Status        string     `json:"status"`
	TransactionID string     `json:"transactionId"`
	StartedAt     time.Time  `json:"startedAt"`
	CompletedAt   *time.Time `json:"completedAt,omitempty"`
	SourceVersion string     `json:"sourceVersion,omitempty"`
	TargetVersion string     `json:"targetVersion,omitempty"`
}

// InstalledState is the on-host record of exactly what is installed,
// matching schemas/installed-state.v1.schema.json.
type InstalledState struct {
	Runtimes            map[string]runtimeconfig.Selection `json:"runtimes,omitempty"`
	SchemaVersion       int                                `json:"schemaVersion"`
	ApplianceInstanceID string                             `json:"applianceInstanceId"`
	InstalledVersion    string                             `json:"installedVersion"`
	InstalledReleaseID  string                             `json:"installedReleaseId"`
	ApplianceProfile    string                             `json:"applianceProfile,omitempty"`
	ApplianceName       string                             `json:"applianceName,omitempty"`
	DNSZone             string                             `json:"dnsZone,omitempty"`
	Cluster             *Cluster                           `json:"cluster,omitempty"`
	Components          Components                         `json:"components"`
	K3sOwnership        K3sOwnership                       `json:"k3sOwnership"`
	LastOperation       Operation                          `json:"lastOperation"`
	History             []Operation                        `json:"history,omitempty"`
	CreatedAt           time.Time                          `json:"createdAt"`
	UpdatedAt           time.Time                          `json:"updatedAt"`
}

// Load reads and schema-validates the installed-state record at path. It
// returns (nil, nil) when the file does not exist, meaning a fresh host
// with no prior installation.
func Load(path string) (*InstalledState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("state: read %s: %w", path, err)
	}

	if err := manifest.Validate(manifest.KindInstalledState, data); err != nil {
		return nil, fmt.Errorf("state: %s does not satisfy installed-state.v1: %w", path, err)
	}

	var s InstalledState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("state: parse %s: %w", path, err)
	}
	return &s, nil
}

// Save schema-validates s and writes it atomically to path.
func Save(path string, s *InstalledState) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("state: marshal installed state: %w", err)
	}

	if err := manifest.Validate(manifest.KindInstalledState, data); err != nil {
		return fmt.Errorf("state: assembled installed state failed schema validation: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("state: create directory for %s: %w", path, err)
	}
	return lifecycle.WriteFileAtomic(path, data, 0o640)
}
