package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cluster"
	"github.com/zoncaesaradmin/appliance-ctl/internal/host"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdirs"
	"github.com/zoncaesaradmin/appliance-ctl/internal/images"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/lifecycle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/nvidia"
	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
	"github.com/zoncaesaradmin/appliance-ctl/internal/runtimeconfig"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

// fileSnapshot preserves an installer-owned file across a worker update. A
// worker has no control-plane rollback agent, so the local updater must be
// able to restore its own binary, config and unit if any post-write step
// fails. The snapshot intentionally contains no token: the token file is
// neither replaced nor read into memory by this operation.
type fileSnapshot struct {
	path   string
	data   []byte
	mode   os.FileMode
	exists bool
}

func snapshotFile(path string) (*fileSnapshot, error) {
	s := &fileSnapshot{path: path}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("snapshot %s: expected a regular file", path)
	}
	s.data, err = os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	s.mode, s.exists = info.Mode().Perm(), true
	return s, nil
}

func (s *fileSnapshot) restore() error {
	if s == nil {
		return nil
	}
	if !s.exists {
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove new %s: %w", s.path, err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return fmt.Errorf("create parent for %s: %w", s.path, err)
	}
	if err := lifecycle.WriteFileAtomic(s.path, s.data, s.mode); err != nil {
		return fmt.Errorf("restore %s: %w", s.path, err)
	}
	return nil
}

// JoinWorkerOptions contains the agent-only additions to Options. A joining
// node never applies appliance charts or advertises mDNS; it verifies and
// preloads the same signed release input locally, then runs K3s as an agent.
type JoinWorkerOptions struct {
	Options
	EnrollmentPath    string
	SignerFingerprint string
	K3sAgentTokenPath string
}

// UpgradeWorkerOptions describes the local, agent-only half of a coordinated
// cluster upgrade. The control plane does not SSH into a worker: each worker
// verifies the same signed offline bundle and updates its own K3s/containerd
// runtime before the control-plane upgrade is allowed to rely on it.
type UpgradeWorkerOptions struct {
	Options
	K3sAgentTokenPath string
}

// UpgradeWorker refreshes a joined worker without applying cluster charts or
// advertising ingress. It intentionally preserves the existing enrollment
// endpoint and token file; a release bundle never carries either secret.
func (o *Orchestrator) UpgradeWorker(ctx context.Context, source Source, opts UpgradeWorkerOptions) (_ *state.InstalledState, returnedErr error) {
	installed, err := state.Load(opts.InstalledStatePath)
	if err != nil || installed == nil || installed.Cluster == nil {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("cluster worker upgrade: local cluster receipt is required")
	}
	if installed.Cluster.ControlPlaneNode == opts.NodeName {
		return nil, errors.New("cluster worker upgrade: control-plane nodes use zonctl upgrade")
	}
	if strings.TrimSpace(installed.Cluster.ControlEndpoint) == "" || strings.TrimSpace(opts.K3sAgentTokenPath) == "" {
		return nil, errors.New("cluster worker upgrade: enrolled control endpoint and agent token path are required")
	}
	if _, err := os.Stat(opts.K3sAgentTokenPath); err != nil {
		return nil, fmt.Errorf("cluster worker upgrade: read preserved agent token: %w", err)
	}
	resolved, _, err := source.Resolve(ctx, installed.ApplianceProfile)
	if err != nil {
		return nil, err
	}
	if resolved.EffectiveProfile != installed.ApplianceProfile {
		return nil, errors.New("cluster worker upgrade: signed bundle profile differs from worker receipt")
	}
	role := state.NodeRoleWorker
	for _, node := range installed.Cluster.Nodes {
		if node.Name == opts.NodeName {
			role = node.Role
			break
		}
	}
	if err := validateInferenceJoinRuntime(role, resolved.Runtimes["inference"], productconfig.HostNVIDIAAvailable()); err != nil {
		return nil, err
	}
	if err := prepareInferenceWorkerStorage(role, o.EnsureOwnedDir); err != nil {
		return nil, err
	}
	// Preserve every file this operation can replace before stopping K3s. This
	// makes an interrupted or failed worker upgrade converge back to the exact
	// prior agent rather than merely restarting an unknown mixture of versions.
	binaryBefore, err := snapshotFile(opts.K3sBinaryDestPath)
	if err != nil {
		return nil, fmt.Errorf("cluster worker upgrade: %w", err)
	}
	configBefore, err := snapshotFile(opts.K3sConfigPath)
	if err != nil {
		return nil, fmt.Errorf("cluster worker upgrade: %w", err)
	}
	unitBefore, err := snapshotFile(opts.K3sUnitPath)
	if err != nil {
		return nil, fmt.Errorf("cluster worker upgrade: %w", err)
	}

	// Do not strand a worker with its K3s agent stopped if a later local
	// validation, runtime, or preload step fails. Restore the files before
	// restarting so the agent returns to its prior coherent configuration.
	stopped, completed := false, false
	defer func() {
		if stopped && !completed {
			var rollbackErrs []error
			for _, snapshot := range []*fileSnapshot{unitBefore, configBefore, binaryBefore} {
				if err := snapshot.restore(); err != nil {
					rollbackErrs = append(rollbackErrs, err)
				}
			}
			if err := o.K3s.DaemonReload(); err != nil {
				rollbackErrs = append(rollbackErrs, err)
			}
			if err := o.K3s.EnableAndStart(opts.K3sUnitName); err != nil {
				rollbackErrs = append(rollbackErrs, err)
			}
			if len(rollbackErrs) > 0 {
				returnedErr = errors.Join(returnedErr, fmt.Errorf("cluster worker upgrade rollback: %w", errors.Join(rollbackErrs...)))
			}
		}
	}()
	if err := o.K3s.Stop(opts.K3sUnitName); err != nil {
		return nil, err
	}
	stopped = true
	if err := o.K3s.InstallBinary(resolved.K3sBinaryPath, opts.K3sBinaryDestPath); err != nil {
		return nil, err
	}
	if err := o.K3s.WriteConfig(opts.K3sConfigPath, k3s.Config{Mode: k3s.NodeModeAgent, NodeName: opts.NodeName, DataDir: opts.K3sDataDir, ServerURL: installed.Cluster.ControlEndpoint, TokenFile: opts.K3sAgentTokenPath}); err != nil {
		return nil, err
	}
	if err := o.K3s.WriteUnit(opts.K3sUnitPath, k3s.UnitConfig{BinaryPath: opts.K3sBinaryDestPath, ConfigPath: opts.K3sConfigPath, Mode: k3s.NodeModeAgent}); err != nil {
		return nil, err
	}
	if err := o.K3s.DaemonReload(); err != nil {
		return nil, err
	}
	if err := o.K3s.EnableAndStart(opts.K3sUnitName); err != nil {
		return nil, err
	}
	if runtimeconfig.RequiresGPU(resolved.Runtimes["inference"]) {
		if err := nvidia.ConfigureLocalK3sRuntime(ctx, o.ImagesRun, nvidia.DefaultContainerdConfig, opts.K3sUnitName, o.K3s.Restart); err != nil {
			return nil, err
		}
	}
	importer := &images.Importer{Run: o.ImagesRun, Namespace: "k8s.io"}
	if err := importer.WaitReady(ctx, containerdReadyTimeout, containerdReadyPollInterval); err != nil {
		return nil, err
	}
	if _, err := importer.PreloadAll(ctx, append(append([]images.Image{}, resolved.K3sImages...), resolved.FilterOCIImages(resolved.OCIImages)...)); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	installed.InstalledVersion, installed.InstalledReleaseID = resolved.BundleVersion, resolved.ReleaseID
	installed.Runtimes = resolved.Runtimes
	installed.Components.K3sVersion, installed.Components.ChartVersion = resolved.Compatibility.K3sVersion, resolved.Compatibility.ChartVersion
	installed.K3sOwnership.OwnerApplianceVersion = resolved.BundleVersion
	installed.LastOperation = state.Operation{Type: "cluster-worker-upgrade", Status: "completed", TransactionID: opts.TransactionID, StartedAt: now, CompletedAt: &now}
	installed.UpdatedAt = now
	if err := state.Save(opts.InstalledStatePath, installed); err != nil {
		return nil, err
	}
	completed = true
	return installed, nil
}

// JoinWorker performs the local half of an explicit cluster enrollment. The
// control-plane must subsequently observe and label the node before workloads
// are scheduled there; this function intentionally does not use discovery.
func (o *Orchestrator) JoinWorker(ctx context.Context, source Source, opts JoinWorkerOptions) (*state.InstalledState, error) {
	enrollment, err := cluster.ReadEnrollment(opts.EnrollmentPath)
	if err != nil {
		return nil, err
	}
	if err := enrollment.Validate(time.Now().UTC(), opts.SignerFingerprint); err != nil {
		return nil, err
	}
	if enrollment.NodeRole == "prime" {
		return nil, errors.New("cluster join: prime enrollment must join as a server")
	}
	if strings.TrimSpace(opts.NodeName) != enrollment.ExpectedNodeName {
		return nil, fmt.Errorf("cluster join: enrollment is for node %q, not %q", enrollment.ExpectedNodeName, opts.NodeName)
	}
	if existing, err := state.Load(opts.InstalledStatePath); err != nil || existing != nil {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("cluster join: this host already has an appliance receipt")
	}
	signal, err := o.K3s.DetectService(opts.K3sUnitName)
	if err != nil {
		return nil, err
	}
	if signal.Detected {
		return nil, errors.New("cluster join: refusing host with existing K3s service")
	}
	resolved, _, err := source.Resolve(ctx, enrollment.ApplianceProfile)
	if err != nil {
		return nil, err
	}
	if resolved.ReleaseID != enrollment.ReleaseID || resolved.BundleVersion != enrollment.ReleaseVersion {
		return nil, errors.New("cluster join: signed bundle release does not match enrollment")
	}
	// An inference worker is accepted only when its local hardware can run the
	// signed runtime selected by the cluster profile. This is intentionally
	// evaluated on the joining node, never inferred from a control-plane label.
	if err := validateInferenceJoinRuntime(enrollment.NodeRole, resolved.Runtimes["inference"], productconfig.HostNVIDIAAvailable()); err != nil {
		return nil, err
	}
	facts, err := o.DetectHost(host.Options{DataDir: opts.K3sDataDir})
	if err != nil {
		return nil, err
	}
	if check := CheckBundleHostBaseline(facts, resolved.HostBaseline); string(check.Status) != "pass" {
		return nil, errors.New("cluster join: target host does not match signed bundle baseline")
	}
	role := state.NodeRoleWorker
	if enrollment.NodeRole == "inference" {
		role = state.NodeRoleInference
	}
	if err := prepareInferenceWorkerStorage(role, o.EnsureOwnedDir); err != nil {
		return nil, err
	}
	if err := writeJoinToken(opts.K3sAgentTokenPath, enrollment.K3sToken); err != nil {
		return nil, err
	}
	rollback := func() {
		_ = os.Remove(opts.K3sAgentTokenPath)
		_ = o.K3s.Stop(opts.K3sUnitName)
		_ = os.Remove(opts.K3sConfigPath)
		_ = os.Remove(opts.K3sUnitPath)
		_ = os.Remove(opts.K3sBinaryDestPath)
		_ = o.K3s.RemoveKubectlSymlink(opts.K3sBinaryDestPath, opts.KubectlSymlinkPath)
		_ = o.K3s.DaemonReload()
		_ = o.K3s.CleanupNodeNetwork(opts.K3sCNINetworkDir, opts.K3sCNIInterfaces)
	}
	if err := o.K3s.WriteConfig(opts.K3sConfigPath, k3s.Config{Mode: k3s.NodeModeAgent, NodeName: opts.NodeName, DataDir: opts.K3sDataDir, ServerURL: enrollment.ControlEndpoint, TokenFile: opts.K3sAgentTokenPath}); err != nil {
		rollback()
		return nil, err
	}
	if err := o.K3s.WriteUnit(opts.K3sUnitPath, k3s.UnitConfig{BinaryPath: opts.K3sBinaryDestPath, ConfigPath: opts.K3sConfigPath, Mode: k3s.NodeModeAgent}); err != nil {
		rollback()
		return nil, err
	}
	if err := o.K3s.InstallBinary(resolved.K3sBinaryPath, opts.K3sBinaryDestPath); err != nil {
		rollback()
		return nil, err
	}
	if err := o.K3s.EnsureKubectlSymlink(opts.K3sBinaryDestPath, opts.KubectlSymlinkPath); err != nil {
		rollback()
		return nil, err
	}
	if err := o.K3s.EnableAndStart(opts.K3sUnitName); err != nil {
		rollback()
		return nil, err
	}
	// An accelerated worker owns the containerd runtime on its own host. Do
	// this after the K3s agent has initialized its generated config and before
	// the control plane is allowed to deploy a node-bound vLLM release. The
	// cluster-scoped RuntimeClass is applied separately by the control-plane
	// deploy command; an agent receipt has no authority to mutate it.
	if runtimeconfig.RequiresGPU(resolved.Runtimes["inference"]) {
		if err := nvidia.ConfigureLocalK3sRuntime(ctx, o.ImagesRun, nvidia.DefaultContainerdConfig, opts.K3sUnitName, o.K3s.Restart); err != nil {
			rollback()
			return nil, fmt.Errorf("cluster join: configure NVIDIA K3s runtime: %w", err)
		}
	}
	importer := &images.Importer{Run: o.ImagesRun, Namespace: "k8s.io"}
	if err := importer.WaitReady(ctx, containerdReadyTimeout, containerdReadyPollInterval); err != nil {
		rollback()
		return nil, err
	}
	if _, err := importer.PreloadAll(ctx, append(append([]images.Image{}, resolved.K3sImages...), resolved.FilterOCIImages(resolved.OCIImages)...)); err != nil {
		rollback()
		return nil, err
	}
	now := time.Now().UTC()
	receipt := &state.InstalledState{SchemaVersion: 1, ApplianceInstanceID: newApplianceInstanceID(), InstalledVersion: resolved.BundleVersion, InstalledReleaseID: resolved.ReleaseID, ApplianceProfile: enrollment.ApplianceProfile, ApplianceName: enrollment.ApplianceName, Cluster: &state.Cluster{ID: enrollment.ClusterID, Topology: state.TopologyServerWorkers, ControlPlaneNode: enrollment.ControlPlaneNode, IngressNode: enrollment.ControlPlaneNode, ControlEndpoint: enrollment.ControlEndpoint, ClusterCAHash: enrollment.ClusterCAHash, EnrollmentSignerFingerprint: opts.SignerFingerprint, ClusterCIDR: k3s.DefaultClusterCIDR, ServiceCIDR: k3s.DefaultServiceCIDR, Nodes: []state.ClusterNode{{ID: enrollment.ControlPlaneNode, Name: enrollment.ControlPlaneNode, Role: state.NodeRoleControlPlane, Roles: []string{state.NodeRoleControlPlane}}, {ID: opts.NodeName, Name: opts.NodeName, Role: role, Roles: []string{role}}}}, Components: state.Components{K3sVersion: resolved.Compatibility.K3sVersion, ChartVersion: resolved.Compatibility.ChartVersion}, K3sOwnership: state.K3sOwnership{Owned: true, OwnerApplianceVersion: resolved.BundleVersion}, LastOperation: state.Operation{Type: "cluster-join", Status: "completed", TransactionID: opts.TransactionID, StartedAt: now, CompletedAt: &now}, CreatedAt: now, UpdatedAt: now}
	if err := state.Save(opts.InstalledStatePath, receipt); err != nil {
		rollback()
		return nil, err
	}
	return receipt, nil
}

// JoinEnrolledNode dispatches member (K3s agent) vs extra-prime (K3s server)
// join from the enrollment role.
func (o *Orchestrator) JoinEnrolledNode(ctx context.Context, source Source, opts JoinWorkerOptions) (*state.InstalledState, error) {
	enrollment, err := cluster.ReadEnrollment(opts.EnrollmentPath)
	if err != nil {
		return nil, err
	}
	if enrollment.NodeRole == "prime" {
		opts.K3sAgentTokenPath = "/etc/rancher/k3s/zon-server-token"
		return o.JoinServer(ctx, source, opts)
	}
	if strings.TrimSpace(opts.K3sAgentTokenPath) == "" {
		opts.K3sAgentTokenPath = "/etc/rancher/k3s/zon-agent-token"
	}
	return o.JoinWorker(ctx, source, opts)
}

// JoinServer enrolls an additional prime (K3s server / etcd peer). It does
// not install charts or advertise mDNS; the first prime remains IngressNode.
func (o *Orchestrator) JoinServer(ctx context.Context, source Source, opts JoinWorkerOptions) (*state.InstalledState, error) {
	enrollment, err := cluster.ReadEnrollment(opts.EnrollmentPath)
	if err != nil {
		return nil, err
	}
	if err := enrollment.Validate(time.Now().UTC(), opts.SignerFingerprint); err != nil {
		return nil, err
	}
	if enrollment.NodeRole != "prime" {
		return nil, fmt.Errorf("cluster join: enrollment role %q is not prime", enrollment.NodeRole)
	}
	if strings.TrimSpace(opts.NodeName) != enrollment.ExpectedNodeName {
		return nil, fmt.Errorf("cluster join: enrollment is for node %q, not %q", enrollment.ExpectedNodeName, opts.NodeName)
	}
	if existing, err := state.Load(opts.InstalledStatePath); err != nil || existing != nil {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("cluster join: this host already has an appliance receipt")
	}
	signal, err := o.K3s.DetectService(opts.K3sUnitName)
	if err != nil {
		return nil, err
	}
	if signal.Detected {
		return nil, errors.New("cluster join: refusing host with existing K3s service")
	}
	resolved, _, err := source.Resolve(ctx, enrollment.ApplianceProfile)
	if err != nil {
		return nil, err
	}
	if resolved.ReleaseID != enrollment.ReleaseID || resolved.BundleVersion != enrollment.ReleaseVersion {
		return nil, errors.New("cluster join: signed bundle release does not match enrollment")
	}
	facts, err := o.DetectHost(host.Options{DataDir: opts.K3sDataDir})
	if err != nil {
		return nil, err
	}
	if check := CheckBundleHostBaseline(facts, resolved.HostBaseline); string(check.Status) != "pass" {
		return nil, errors.New("cluster join: target host does not match signed bundle baseline")
	}
	tokenPath := opts.K3sAgentTokenPath
	if strings.TrimSpace(tokenPath) == "" {
		tokenPath = "/etc/rancher/k3s/zon-server-token"
	}
	if err := writeJoinToken(tokenPath, enrollment.K3sToken); err != nil {
		return nil, err
	}
	rollback := func() {
		_ = os.Remove(tokenPath)
		_ = o.K3s.Stop(opts.K3sUnitName)
		_ = os.Remove(opts.K3sConfigPath)
		_ = os.Remove(opts.K3sUnitPath)
		_ = os.Remove(opts.K3sBinaryDestPath)
		_ = o.K3s.RemoveKubectlSymlink(opts.K3sBinaryDestPath, opts.KubectlSymlinkPath)
		_ = o.K3s.DaemonReload()
		_ = o.K3s.CleanupNodeNetwork(opts.K3sCNINetworkDir, opts.K3sCNIInterfaces)
	}
	if err := o.K3s.WriteConfig(opts.K3sConfigPath, k3s.Config{
		Mode:      k3s.NodeModeServer,
		NodeName:  opts.NodeName,
		DataDir:   opts.K3sDataDir,
		ServerURL: enrollment.ControlEndpoint,
		TokenFile: tokenPath,
		TLSSANs:   opts.TLSSANs,
	}); err != nil {
		rollback()
		return nil, err
	}
	if err := o.K3s.WriteUnit(opts.K3sUnitPath, k3s.UnitConfig{BinaryPath: opts.K3sBinaryDestPath, ConfigPath: opts.K3sConfigPath, Mode: k3s.NodeModeServer}); err != nil {
		rollback()
		return nil, err
	}
	if err := o.K3s.InstallBinary(resolved.K3sBinaryPath, opts.K3sBinaryDestPath); err != nil {
		rollback()
		return nil, err
	}
	if err := o.K3s.EnsureKubectlSymlink(opts.K3sBinaryDestPath, opts.KubectlSymlinkPath); err != nil {
		rollback()
		return nil, err
	}
	if err := o.K3s.EnableAndStart(opts.K3sUnitName); err != nil {
		rollback()
		return nil, err
	}
	importer := &images.Importer{Run: o.ImagesRun, Namespace: "k8s.io"}
	if err := importer.WaitReady(ctx, containerdReadyTimeout, containerdReadyPollInterval); err != nil {
		rollback()
		return nil, err
	}
	if _, err := importer.PreloadAll(ctx, append(append([]images.Image{}, resolved.K3sImages...), resolved.FilterOCIImages(resolved.OCIImages)...)); err != nil {
		rollback()
		return nil, err
	}
	now := time.Now().UTC()
	receipt := &state.InstalledState{
		SchemaVersion:       1,
		ApplianceInstanceID: newApplianceInstanceID(),
		InstalledVersion:    resolved.BundleVersion,
		InstalledReleaseID:  resolved.ReleaseID,
		ApplianceProfile:    enrollment.ApplianceProfile,
		ApplianceName:       enrollment.ApplianceName,
		Cluster: &state.Cluster{
			ID:                          enrollment.ClusterID,
			Topology:                    state.TopologyMultiServer,
			ControlPlaneNode:            enrollment.ControlPlaneNode,
			IngressNode:                 enrollment.ControlPlaneNode,
			ControlEndpoint:             enrollment.ControlEndpoint,
			ClusterCAHash:               enrollment.ClusterCAHash,
			EnrollmentSignerFingerprint: opts.SignerFingerprint,
			ClusterCIDR:                 k3s.DefaultClusterCIDR,
			ServiceCIDR:                 k3s.DefaultServiceCIDR,
			Nodes: []state.ClusterNode{
				{ID: enrollment.ControlPlaneNode, Name: enrollment.ControlPlaneNode, Role: state.NodeRoleControlPlane, Roles: []string{state.NodeRoleControlPlane}},
				{ID: opts.NodeName, Name: opts.NodeName, Role: state.NodeRoleControlPlane, Roles: []string{state.NodeRoleControlPlane}},
			},
		},
		Components:    state.Components{K3sVersion: resolved.Compatibility.K3sVersion, ChartVersion: resolved.Compatibility.ChartVersion},
		K3sOwnership:  state.K3sOwnership{Owned: true, OwnerApplianceVersion: resolved.BundleVersion},
		LastOperation: state.Operation{Type: "cluster-join", Status: "completed", TransactionID: opts.TransactionID, StartedAt: now, CompletedAt: &now},
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := state.Save(opts.InstalledStatePath, receipt); err != nil {
		rollback()
		return nil, err
	}
	return receipt, nil
}

func validateInferenceJoinRuntime(role string, runtime runtimeconfig.Selection, gpuAvailable bool) error {
	if role != "inference" {
		return nil
	}
	if strings.TrimSpace(runtime.Package) == "" {
		return errors.New("cluster join: inference role requires a signed inference runtime")
	}
	if runtimeconfig.RequiresGPU(runtime) && !gpuAvailable {
		return fmt.Errorf("cluster join: inference runtime package %q requires a usable local NVIDIA GPU", runtime.Package)
	}
	return nil
}

func prepareInferenceWorkerStorage(role string, ensure func(path string, uid, gid int, perm os.FileMode) error) error {
	if role != state.NodeRoleInference {
		return nil
	}
	if ensure == nil {
		return errors.New("cluster join: inference storage preparation is not configured")
	}
	if err := ensure(hostdirs.InferenceModelsDir, hostdirs.InferenceDirOwnerUID, hostdirs.ApplianceSharedFSGID, hostdirs.WorkspaceDirMode); err != nil {
		return fmt.Errorf("cluster join: prepare inference models directory: %w", err)
	}
	return nil
}

func writeJoinToken(path, token string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("cluster join: create token directory: %w", err)
	}
	if err := lifecycle.WriteFileAtomic(path, []byte(token+"\n"), 0o600); err != nil {
		return fmt.Errorf("cluster join: write token: %w", err)
	}
	return nil
}
