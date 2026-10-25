package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cluster"
	"github.com/zoncaesaradmin/appliance-ctl/internal/clustertopology"
)

func TestClusterServerEnrollmentUsesStagedInventoryAndProtectedArtifact(t *testing.T) {
	root := t.TempDir()
	inventoryPath := filepath.Join(root, "inventory.json")
	content := `{"topology":"embedded-etcd-v1","bootstrapNode":"server-a","nodes":[{"name":"server-a","address":"10.0.0.11"},{"name":"server-b","address":"10.0.0.12"},{"name":"server-c","address":"10.0.0.13"}]}`
	if err := os.WriteFile(inventoryPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	inventory, err := clustertopology.Load(inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, _ := inventory.Fingerprint()
	_, signerFingerprint, err := cluster.LoadOrCreateSigner(filepath.Join(root, "cluster-enrollment-ed25519.key"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	staged := clustertopology.BootstrapState{
		SchemaVersion: clustertopology.BootstrapStateVersion, Topology: clustertopology.EmbeddedEtcdV1,
		InventoryFingerprint: fingerprint, ClusterID: "cluster-1", ApplianceName: "zon", ApplianceProfile: "core", DNSZone: "appliance.internal",
		ReleaseID: "release-1", BundleVersion: "2.4.0", K3sVersion: "v1.30.4+k3s1", LocalNode: "server-a",
		Phase: clustertopology.PhaseServerReady, EnrollmentSignerFingerprint: signerFingerprint, CreatedAt: now, UpdatedAt: now,
	}
	if err := clustertopology.SaveBootstrapState(filepath.Join(root, "cluster-bootstrap-state.json"), staged); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(root, "server-ca.crt")
	if err := os.WriteFile(caPath, []byte("test-ca"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldCAPath, oldTokenRead := clusterServerCAPath, clusterServerTokenRead
	clusterServerCAPath = caPath
	clusterServerTokenRead = func() (string, error) { return "K10test-server-token", nil }
	t.Cleanup(func() { clusterServerCAPath, clusterServerTokenRead = oldCAPath, oldTokenRead })
	output := filepath.Join(root, "server-b.enrollment")
	opts := cliOptions{stateDir: root, nodeName: "server-a", clusterInventoryPath: inventoryPath, serverName: "server-b", enrollmentOut: output, enrollmentTTL: "15m"}
	result := runClusterServerEnrollmentCreate(opts, commandResult{Command: "cluster-server-enrollment-create"})
	if result.Status != "succeeded" {
		t.Fatalf("enrollment creation failed: %+v", result)
	}
	artifact, err := cluster.ReadEnrollment(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := artifact.Validate(time.Now().UTC(), signerFingerprint); err != nil {
		t.Fatal(err)
	}
	if artifact.DNSZone != staged.DNSZone || artifact.InventoryFingerprint != fingerprint || artifact.ExpectedNodeName != "server-b" || artifact.K3sToken != "K10test-server-token" {
		t.Fatalf("incorrect enrollment fields: %+v", artifact)
	}
	if info, err := os.Stat(output); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("enrollment permissions = %v, %v", info, err)
	}
	if duplicate := runClusterServerEnrollmentCreate(opts, commandResult{}); duplicate.Status != "failed" {
		t.Fatal("existing enrollment was overwritten")
	}
	opts.serverName = "unlisted"
	opts.enrollmentOut = filepath.Join(root, "invalid.enrollment")
	if invalid := runClusterServerEnrollmentCreate(opts, commandResult{}); invalid.Status != "failed" {
		t.Fatal("unlisted server was enrolled")
	}
}
