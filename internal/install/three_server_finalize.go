package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cluster"
	"github.com/zoncaesaradmin/appliance-ctl/internal/clustertopology"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

// FinalizeEmbeddedEtcd is the only path that turns a staged embedded-etcd
// substrate into an installed appliance. It deploys product charts once from
// the bootstrap server only after Kubernetes reports every planned
// control-plane and embedded-etcd node Ready and every direct API address
// accepts the trusted credential.
func (o *Orchestrator) FinalizeEmbeddedEtcd(ctx context.Context, source Source, opts Options) (*state.InstalledState, []evidence.Check, error) {
	resolved, checks, err := source.Resolve(ctx, opts.ApplianceProfile)
	if err != nil {
		return nil, checks, err
	}
	if resolved.Compatibility.DeploymentTopology != clustertopology.EmbeddedEtcdV1 {
		return nil, checks, errors.New("cluster finalize: signed bundle does not require embedded etcd")
	}
	inventory, err := clustertopology.Load(opts.ClusterInventoryPath)
	if err != nil {
		return nil, checks, err
	}
	if opts.NodeName != inventory.BootstrapNode {
		return nil, checks, errors.New("cluster finalize: product charts may only be deployed from the bootstrap server")
	}
	identity, err := productconfig.ResolveApplianceIdentity(opts.ApplianceName, opts.DNSZone)
	if err != nil {
		return nil, checks, err
	}
	localAddresses := o.LocalAddresses
	if localAddresses == nil {
		localAddresses = clustertopology.LocalAddresses
	}
	addresses, err := localAddresses()
	if err != nil {
		return nil, checks, err
	}
	if err := inventory.ValidateLocalAddress(opts.NodeName, addresses); err != nil {
		return nil, checks, err
	}
	stagePath := filepath.Join(filepath.Dir(opts.InstalledStatePath), "cluster-bootstrap-state.json")
	staged, err := clustertopology.LoadBootstrapState(stagePath)
	if err != nil {
		return nil, checks, err
	}
	if staged == nil || (staged.Phase != clustertopology.PhaseServerReady && staged.Phase != clustertopology.PhaseFinalized) {
		return nil, checks, errors.New("cluster finalize: bootstrap server has not completed the staged K3s phase")
	}
	if err := staged.Matches(inventory, resolved.ReleaseID, resolved.BundleVersion, resolved.Compatibility.K3sVersion, opts.NodeName, identity.Name, resolved.EffectiveProfile, identity.Zone); err != nil {
		return nil, checks, err
	}
	if strings.TrimSpace(staged.EnrollmentSignerFingerprint) == "" {
		return nil, checks, errors.New("cluster finalize: staged enrollment signer is missing")
	}
	signal, err := o.K3s.DetectService(opts.K3sUnitName)
	if err != nil || !signal.Active {
		return nil, checks, errors.New("cluster finalize: staged K3s server is not active")
	}
	if current, err := o.K3s.Version(opts.K3sBinaryDestPath); err != nil || current != resolved.Compatibility.K3sVersion {
		return nil, checks, errors.New("cluster finalize: local K3s binary differs from the signed release")
	}
	nodes := cluster.ValidateEmbeddedEtcdNodeReadiness(ctx, o.HelmRun, opts.KubeconfigPath, inventory, resolved.Compatibility.K3sVersion, nil)
	apis := cluster.ValidateEmbeddedEtcdAPIEndpoints(ctx, o.HelmRun, opts.KubeconfigPath, inventory)
	if !nodes.Healthy || !apis.Healthy {
		return nil, checks, fmt.Errorf("cluster finalize: substrate not ready: Kubernetes=%s; direct APIs=%s", nodes.Message, apis.Message)
	}
	if staged.Phase == clustertopology.PhaseFinalized {
		installed, err := state.Load(opts.InstalledStatePath)
		if err != nil || installed == nil || installed.Cluster == nil || installed.ApplianceInstanceID != staged.ClusterID || installed.InstalledReleaseID != resolved.ReleaseID {
			return nil, checks, errors.New("cluster finalize: finalized bootstrap receipt does not match the installed appliance")
		}
		return installed, checks, nil
	}
	members := make([]state.ClusterNode, 0, len(inventory.Nodes))
	bootstrapUID := ""
	for _, node := range inventory.Nodes {
		uid, err := cluster.NodeUID(ctx, o.HelmRun, opts.KubeconfigPath, node.Name)
		if err != nil {
			return nil, checks, err
		}
		if node.Name == inventory.BootstrapNode {
			bootstrapUID = uid
		}
		members = append(members, state.ClusterNode{ID: node.Name, Name: node.Name, NodeUID: uid, Role: state.NodeRoleControlPlane, Roles: []string{state.NodeRoleControlPlane, "etcd"}})
	}
	caHash, err := serverCAHash(opts.K3sDataDir)
	if err != nil {
		return nil, checks, err
	}
	finalization := &EmbeddedEtcdFinalization{
		ClusterID: staged.ClusterID, ControlPlaneNode: inventory.BootstrapNode,
		ControlEndpoint: inventory.BootstrapAPIEndpoint(), ControlEndpoints: inventory.APIEndpoints(),
		ClusterCAHash: caHash, EnrollmentSignerFingerprint: staged.EnrollmentSignerFingerprint, Nodes: members,
	}
	finalOpts := opts
	finalOpts.EmbeddedEtcdFinalization = finalization
	finalOpts.TLSSANs = appendUniqueStrings(inventory.APISANs(), opts.TLSSANs...)
	installed, installChecks, err := o.Install(ctx, source, finalOpts)
	checks = append(checks, installChecks...)
	if err != nil {
		return nil, checks, err
	}
	staged.Phase = clustertopology.PhaseFinalized
	staged.NodeUID = bootstrapUID
	staged.UpdatedAt = time.Now().UTC()
	if err := clustertopology.SaveBootstrapState(stagePath, *staged); err != nil {
		return nil, checks, fmt.Errorf("cluster finalize: record completion: %w", err)
	}
	return installed, checks, nil
}

func serverCAHash(k3sDataDir string) (string, error) {
	ca, err := os.ReadFile(filepath.Join(k3sDataDir, "server", "tls", "server-ca.crt"))
	if err != nil {
		return "", fmt.Errorf("cluster finalize: read K3s server CA: %w", err)
	}
	digest := sha256.Sum256(ca)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func appendUniqueStrings(first []string, rest ...string) []string {
	result := make([]string, 0, len(first)+len(rest))
	seen := map[string]struct{}{}
	for _, value := range append(append([]string(nil), first...), rest...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, found := seen[value]; !found {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftSeen, rightSeen := map[string]struct{}{}, map[string]struct{}{}
	for _, value := range left {
		leftSeen[value] = struct{}{}
	}
	for _, value := range right {
		rightSeen[value] = struct{}{}
	}
	if len(leftSeen) != len(rightSeen) {
		return false
	}
	for value := range leftSeen {
		if _, found := rightSeen[value]; !found {
			return false
		}
	}
	return true
}
