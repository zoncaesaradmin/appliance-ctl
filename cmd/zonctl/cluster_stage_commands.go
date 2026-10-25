package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cluster"
	"github.com/zoncaesaradmin/appliance-ctl/internal/clustertopology"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdirs"
	"github.com/zoncaesaradmin/appliance-ctl/internal/install"
	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
)

func runClusterServerStage(ctx context.Context, opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	if strings.TrimSpace(opts.bundleDir) == "" || strings.TrimSpace(opts.clusterInventoryPath) == "" {
		return finish(result, "failed", 2, "cluster-server-stage: --bundle-dir and --cluster-inventory are required", nil)
	}
	if opts.dryRun {
		return finish(result, "succeeded", 0, "cluster-server-stage: verified static inputs; no host changes in dry-run", nil)
	}
	source, err := resolveInstallSource(opts)
	if err != nil {
		return finish(result, "failed", 1, "cluster-server-stage: "+err.Error(), nil)
	}
	registry, err := resolveImagePullRegistry(opts, nil)
	if err != nil {
		return finish(result, "failed", 1, "cluster-server-stage: "+err.Error(), nil)
	}
	stageOpts := install.EmbeddedEtcdStageOptions{
		Options: install.Options{
			ApplianceName:               opts.applianceName,
			DNSZone:                     opts.dnsZone,
			ApplianceProfile:            productconfig.SelectApplianceProfile(opts.applianceProfile, ""),
			ClusterInventoryPath:        opts.clusterInventoryPath,
			NodeName:                    opts.nodeName,
			InstalledStatePath:          filepath.Join(opts.stateDir, "installed-state.json"),
			K3sConfigPath:               defaultK3sConfigPath,
			K3sRegistriesPath:           defaultK3sRegistriesPath,
			K3sUnitPath:                 defaultK3sUnitPath,
			K3sBinaryDestPath:           defaultK3sBinaryDestPath,
			KubectlSymlinkPath:          defaultKubectlSymlinkPath,
			K3sDataDir:                  defaultK3sDataDir,
			KubeconfigPath:              defaultKubeconfigPath,
			K3sUnitName:                 defaultK3sUnitName,
			ControlPlaneDatabaseDataDir: hostdirs.ControlPlaneDatabaseDataDir,
			ClusterInit:                 opts.clusterInit,
			ForceAdopt:                  opts.forceAdopt,
			ImagePullRegistry:           registry,
		},
		EnrollmentPath:      opts.enrollmentFile,
		SignerFingerprint:   opts.clusterSignerFingerprint,
		ServerTokenFilePath: "/etc/rancher/k3s/zon-server-token",
	}
	staged, checks, err := install.NewOrchestrator().StageEmbeddedEtcd(ctx, source, stageOpts)
	if err != nil {
		logger.Error("embedded-etcd substrate stage failed", "error", err, "checks", len(checks))
		return finish(result, "failed", 1, "cluster-server-stage: "+err.Error(), nil)
	}
	data, _ := json.Marshal(map[string]any{"phase": staged.Phase, "clusterComplete": false, "localNode": staged.LocalNode})
	return finish(result, "succeeded", 0, "cluster-server-stage: local K3s server staged; appliance installation is incomplete", data)
}

// runClusterFinalize deploys the product only after the signed one- or
// embedded-etcd K3s inventory has been staged. It does not adopt an arbitrary
// existing cluster.
func runClusterFinalize(ctx context.Context, opts cliOptions, txnID string, logger *slog.Logger, result commandResult) commandResult {
	if strings.TrimSpace(opts.bundleDir) == "" || strings.TrimSpace(opts.clusterInventoryPath) == "" {
		return finish(result, "failed", 2, "cluster-finalize: --bundle-dir and --cluster-inventory are required", nil)
	}
	if opts.dryRun {
		return finish(result, "succeeded", 0, "cluster-finalize: verified static inputs; no product deployment in dry-run", nil)
	}
	profile := productconfig.SelectApplianceProfile(opts.applianceProfile, "")
	source, resolved, _, err := resolveVerifiedInstallSource(ctx, opts, profile)
	if err != nil {
		return finish(result, "failed", 1, "cluster-finalize: "+err.Error(), nil)
	}
	if resolved.Compatibility.DeploymentTopology != clustertopology.EmbeddedEtcdV1 {
		return finish(result, "failed", 1, "cluster-finalize: verified bundle does not declare embedded etcd", nil)
	}
	registry, err := resolveImagePullRegistry(opts, nil)
	if err != nil {
		return finish(result, "failed", 1, "cluster-finalize: "+err.Error(), nil)
	}
	finalOpts := install.Options{
		ApplianceVersion:            version,
		ClusterInventoryPath:        opts.clusterInventoryPath,
		InstalledStatePath:          filepath.Join(opts.stateDir, "installed-state.json"),
		K3sConfigPath:               defaultK3sConfigPath,
		K3sRegistriesPath:           defaultK3sRegistriesPath,
		K3sDataDir:                  defaultK3sDataDir,
		K3sUnitPath:                 defaultK3sUnitPath,
		K3sBinaryDestPath:           defaultK3sBinaryDestPath,
		KubectlSymlinkPath:          defaultKubectlSymlinkPath,
		K3sCNINetworkDir:            defaultK3sCNINetworkDir,
		K3sCNIInterfaces:            append([]string(nil), defaultK3sCNIInterfaces...),
		K3sUnitName:                 defaultK3sUnitName,
		KubeconfigPath:              defaultKubeconfigPath,
		HostAgentBinaryDestPath:     defaultHostAgentBinaryPath,
		HostAgentUnitPath:           defaultHostAgentUnitPath,
		HostAgentUnitName:           defaultHostAgentUnitName,
		HostAgentSocketPath:         defaultHostAgentSocketPath,
		HostAgentLogPath:            defaultHostAgentLogPath,
		ApplianceProfile:            profile,
		WorkspaceRootDir:            defaultWorkspaceRootDir,
		MetadataBundlesDir:          hostdirs.MetadataBundlesDir,
		ControlPlaneDatabaseDataDir: hostdirs.ControlPlaneDatabaseDataDir,
		NodeName:                    opts.nodeName,
		ApplianceName:               opts.applianceName,
		DNSZone:                     opts.dnsZone,
		TLSSANs:                     installTLSSANs(opts),
		ZonctlRealDestPath:          defaultZonctlRealPath,
		ZonctlLauncherDestPath:      defaultZonctlLauncherPath,
		ChartReleaseName:            defaultChartReleaseName,
		ChartNamespace:              defaultChartNamespace,
		TransactionID:               txnID,
		BootstrapMode:               install.BootstrapFresh,
		ImagePullRegistry:           registry,
	}
	installed, checks, err := install.NewOrchestrator().FinalizeEmbeddedEtcd(ctx, source, finalOpts)
	if err != nil {
		logger.Error("embedded-etcd cluster finalization failed", "error", err, "checks", len(checks))
		return finish(result, "failed", 1, "cluster-finalize: "+err.Error(), nil)
	}
	kubernetesHA := installed.Cluster != nil && len(installed.Cluster.ControlEndpoints) == 3
	data, _ := json.Marshal(map[string]any{"installedVersion": installed.InstalledVersion, "releaseId": installed.InstalledReleaseID, "clusterComplete": true, "kubernetesHA": kubernetesHA, "applicationHA": false, "apiEndpoints": installed.Cluster.ControlEndpoints})
	return finish(result, "succeeded", 0, "cluster-finalize: product deployed after embedded-etcd Kubernetes gate; application HA is not established", data)
}

// runClusterServerEnrollmentCreate writes a short-lived, signed credential
// for one of the two inventory peers. The server token is never printed or
// stored in the non-secret bootstrap receipt.
func runClusterServerEnrollmentCreate(opts cliOptions, result commandResult) commandResult {
	const command = "cluster-server-enrollment-create: "
	if opts.clusterInventoryPath == "" || opts.serverName == "" || opts.enrollmentOut == "" {
		return finish(result, "failed", 2, command+"--cluster-inventory, --server-name, and --enrollment-out are required", nil)
	}
	if !filepath.IsAbs(opts.enrollmentOut) {
		return finish(result, "failed", 2, command+"--enrollment-out must be absolute", nil)
	}
	inventory, err := clustertopology.Load(opts.clusterInventoryPath)
	if err != nil {
		return finish(result, "failed", 1, command+err.Error(), nil)
	}
	if opts.nodeName != inventory.BootstrapNode || !inventory.HasNode(opts.serverName) || opts.serverName == inventory.BootstrapNode {
		return finish(result, "failed", 1, command+"run on the bootstrap server for one of its two inventory peers", nil)
	}
	ttl, err := time.ParseDuration(opts.enrollmentTTL)
	if err != nil || ttl < minimumEnrollmentTTL || ttl > maximumEnrollmentTTL {
		return finish(result, "failed", 2, command+"--enrollment-ttl must be between 1m and 24h", nil)
	}
	statePath := filepath.Join(opts.stateDir, "cluster-bootstrap-state.json")
	staged, err := clustertopology.LoadBootstrapState(statePath)
	if err != nil {
		return finish(result, "failed", 1, command+err.Error(), nil)
	}
	if staged == nil || (staged.Phase != clustertopology.PhaseServerReady && staged.Phase != clustertopology.PhaseJoined) {
		return finish(result, "failed", 1, command+"bootstrap server is not staged and ready", nil)
	}
	fingerprint, _ := inventory.Fingerprint()
	if staged.LocalNode != opts.nodeName || staged.InventoryFingerprint != fingerprint || staged.Topology != clustertopology.EmbeddedEtcdV1 {
		return finish(result, "failed", 1, command+"inventory differs from the staged bootstrap server", nil)
	}
	if _, err := os.Stat(opts.enrollmentOut); err == nil {
		return finish(result, "failed", 1, command+"output artifact already exists", nil)
	} else if !os.IsNotExist(err) {
		return finish(result, "failed", 1, command+err.Error(), nil)
	}
	if opts.dryRun {
		return finish(result, "succeeded", 0, fmt.Sprintf("%swould create protected enrollment for server %q", command, opts.serverName), nil)
	}
	signerPath := filepath.Join(opts.stateDir, "cluster-enrollment-ed25519.key")
	if _, err := os.Stat(signerPath); err != nil {
		return finish(result, "failed", 1, command+"staged enrollment signer is missing", nil)
	}
	private, signerFingerprint, err := cluster.LoadOrCreateSigner(signerPath)
	if err != nil || signerFingerprint != staged.EnrollmentSignerFingerprint {
		return finish(result, "failed", 1, command+"staged enrollment signer does not match local key", nil)
	}
	token, err := clusterServerTokenRead()
	if err != nil || strings.TrimSpace(token) == "" {
		return finish(result, "failed", 1, command+"cannot read K3s server token", nil)
	}
	token = strings.TrimSpace(token)
	ca, err := os.ReadFile(clusterServerCAPath)
	if err != nil {
		return finish(result, "failed", 1, command+"cannot read K3s server CA", nil)
	}
	caDigest := sha256.Sum256(ca)
	now := time.Now().UTC()
	nonce, err := cluster.NewNonce()
	if err != nil {
		return finish(result, "failed", 1, command+"cannot create enrollment nonce", nil)
	}
	enrollment := cluster.Enrollment{
		ClusterID: staged.ClusterID, ApplianceName: staged.ApplianceName, ApplianceProfile: staged.ApplianceProfile, DNSZone: staged.DNSZone,
		ControlPlaneNode: inventory.BootstrapNode, NodeRole: "server", DeploymentTopology: staged.Topology, InventoryFingerprint: fingerprint,
		ReleaseID: staged.ReleaseID, ReleaseVersion: staged.BundleVersion, ControlEndpoint: inventory.BootstrapAPIEndpoint(),
		ClusterCAHash: "sha256:" + hex.EncodeToString(caDigest[:]), ExpectedNodeName: opts.serverName,
		K3sToken: token, TokenFingerprint: cluster.TokenFingerprint(token), IssuedAt: now, ExpiresAt: now.Add(ttl), Nonce: nonce,
	}
	if err := enrollment.SignEmbeddedEtcd(private); err != nil {
		return finish(result, "failed", 1, command+err.Error(), nil)
	}
	if err := enrollment.Validate(now, signerFingerprint); err != nil {
		return finish(result, "failed", 1, command+err.Error(), nil)
	}
	if err := cluster.WriteEnrollment(opts.enrollmentOut, enrollment); err != nil {
		return finish(result, "failed", 1, command+"write enrollment: "+err.Error(), nil)
	}
	data, _ := json.Marshal(map[string]string{"clusterId": staged.ClusterID, "expectedNodeName": opts.serverName, "expiresAt": enrollment.ExpiresAt.Format(time.RFC3339), "signerFingerprint": signerFingerprint, "enrollmentPath": opts.enrollmentOut})
	return finish(result, "succeeded", 0, fmt.Sprintf("%sprotected enrollment created for server %q", command, opts.serverName), data)
}
