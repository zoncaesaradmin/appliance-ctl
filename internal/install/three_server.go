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
	"github.com/zoncaesaradmin/appliance-ctl/internal/host"
	"github.com/zoncaesaradmin/appliance-ctl/internal/images"
	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/preflight"
	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

// EmbeddedEtcdStageOptions adds protected server enrollment inputs to the
// ordinary host paths. The bootstrap server has no enrollment artifact;
// joining servers require a signed, inventory-bound v2 artifact.
type EmbeddedEtcdStageOptions struct {
	Options
	EnrollmentPath      string
	SignerFingerprint   string
	ServerTokenFilePath string
}

// StageEmbeddedEtcd installs only K3s and preloads the verified release on a
// server. It never deploys product charts or writes InstalledState. Its
// separate bootstrap receipt makes interrupted staging rerunnable without
// treating the appliance as complete.
func (o *Orchestrator) StageEmbeddedEtcd(ctx context.Context, source Source, opts EmbeddedEtcdStageOptions) (*clustertopology.BootstrapState, []evidence.Check, error) {
	base := opts.Options
	resolved, checks, err := source.Resolve(ctx, base.ApplianceProfile)
	if err != nil {
		return nil, checks, err
	}
	if resolved.Compatibility.DeploymentTopology != clustertopology.EmbeddedEtcdV1 {
		return nil, checks, errors.New("cluster server stage: signed bundle does not require embedded etcd")
	}
	identity, err := productconfig.ResolveApplianceIdentity(base.ApplianceName, base.DNSZone)
	if err != nil {
		return nil, checks, err
	}
	inventory, err := clustertopology.Load(base.ClusterInventoryPath)
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
	if err := inventory.ValidateLocalAddress(base.NodeName, addresses); err != nil {
		return nil, checks, err
	}
	if base.ForceAdopt || base.ClusterInit {
		return nil, checks, errors.New("cluster server stage: force adoption and manual cluster-init are not supported")
	}
	for _, path := range []string{base.InstalledStatePath, base.K3sConfigPath, base.K3sUnitPath, base.K3sBinaryDestPath, base.K3sDataDir, base.KubeconfigPath} {
		if !filepath.IsAbs(path) {
			return nil, checks, errors.New("cluster server stage: all host paths must be absolute")
		}
	}
	if installed, err := state.Load(base.InstalledStatePath); err != nil {
		return nil, checks, err
	} else if installed != nil {
		return nil, checks, errors.New("cluster server stage: an installed appliance receipt exists; use the qualified migration path")
	}
	bootstrap := base.NodeName == inventory.BootstrapNode
	var enrollment cluster.Enrollment
	if bootstrap {
		if strings.TrimSpace(opts.EnrollmentPath) != "" {
			return nil, checks, errors.New("cluster server stage: bootstrap node must not consume an enrollment artifact")
		}
	} else {
		if strings.TrimSpace(opts.EnrollmentPath) == "" || !filepath.IsAbs(opts.ServerTokenFilePath) {
			return nil, checks, errors.New("cluster server stage: joining server requires an enrollment artifact and absolute protected token-file path")
		}
		enrollment, err = cluster.ReadEnrollment(opts.EnrollmentPath)
		if err != nil {
			return nil, checks, err
		}
		if err := enrollment.Validate(time.Now().UTC(), opts.SignerFingerprint); err != nil {
			return nil, checks, err
		}
		fingerprint, err := inventory.Fingerprint()
		if err != nil {
			return nil, checks, err
		}
		if enrollment.Version != cluster.EmbeddedEtcdEnrollmentVersion || enrollment.DeploymentTopology != clustertopology.EmbeddedEtcdV1 || enrollment.InventoryFingerprint != fingerprint || enrollment.ExpectedNodeName != base.NodeName || enrollment.ControlPlaneNode != inventory.BootstrapNode || enrollment.ControlEndpoint != inventory.BootstrapAPIEndpoint() || enrollment.ReleaseID != resolved.ReleaseID || enrollment.ReleaseVersion != resolved.BundleVersion || enrollment.ApplianceProfile != resolved.EffectiveProfile || enrollment.ApplianceName != identity.Name || enrollment.DNSZone != identity.Zone {
			return nil, checks, errors.New("cluster server stage: signed enrollment does not match release, inventory, or target node")
		}
	}
	stagePath := filepath.Join(filepath.Dir(base.InstalledStatePath), "cluster-bootstrap-state.json")
	staged, err := clustertopology.LoadBootstrapState(stagePath)
	if err != nil {
		return nil, checks, err
	}
	renewRelease := false
	if staged != nil {
		if err := staged.MatchesSubstrate(inventory, resolved.Compatibility.K3sVersion, base.NodeName, identity.Name, resolved.EffectiveProfile, identity.Zone); err != nil {
			return nil, checks, err
		}
		renewRelease = staged.ReleaseID != resolved.ReleaseID || staged.BundleVersion != resolved.BundleVersion
		if !bootstrap && (staged.ClusterID != enrollment.ClusterID || staged.EnrollmentSignerFingerprint != opts.SignerFingerprint) {
			return nil, checks, errors.New("cluster server stage: enrollment differs from the staged cluster")
		}
	}
	signal, err := o.K3s.DetectService(base.K3sUnitName)
	if err != nil {
		return nil, checks, err
	}
	if staged == nil && signal.Detected {
		return nil, checks, errors.New("cluster server stage: existing K3s service has no matching bootstrap receipt")
	}
	if staged != nil && signal.Detected {
		if currentVersion, err := o.K3s.Version(base.K3sBinaryDestPath); err != nil || currentVersion != resolved.Compatibility.K3sVersion {
			return nil, checks, errors.New("cluster server stage: existing K3s binary differs from signed release")
		}
	}
	if staged == nil {
		occupied, err := nonEmptyDirectory(base.K3sDataDir)
		if err != nil {
			return nil, checks, err
		}
		if occupied {
			return nil, checks, errors.New("cluster server stage: K3s data directory is not empty; preserve it for explicit recovery")
		}
		if !bootstrap {
			if _, err := os.Stat(opts.ServerTokenFilePath); err == nil {
				return nil, checks, errors.New("cluster server stage: protected token path already exists without a bootstrap receipt")
			} else if !os.IsNotExist(err) {
				return nil, checks, err
			}
		}
	}
	config, err := k3s.EmbeddedEtcdConfig(inventory, base.NodeName, base.K3sDataDir, opts.ServerTokenFilePath)
	if err != nil {
		return nil, checks, err
	}
	if staged != nil {
		if current, err := os.ReadFile(base.K3sConfigPath); err == nil && string(current) != config.Render() {
			return nil, checks, errors.New("cluster server stage: existing K3s config differs from the inventory-bound configuration")
		} else if err != nil && (signal.Detected || !os.IsNotExist(err)) {
			return nil, checks, err
		}
	}
	detectHost := o.DetectHost
	if detectHost == nil {
		detectHost = host.Detect
	}
	requiredPorts := append(append([]int(nil), preflight.RequiredPorts...), 2379, 2380)
	facts, err := detectHost(host.Options{DataDir: base.K3sDataDir, RequiredPorts: requiredPorts})
	if err != nil {
		return nil, checks, err
	}
	if staged != nil && signal.Active {
		for _, port := range requiredPorts {
			delete(facts.PortsInUse, port)
		}
	}
	preflightChecks := preflight.Run(facts)
	checks = append(checks, toEvidenceChecks(preflightChecks)...)
	if overall := preflight.OverallStatus(preflightChecks); overall == preflight.StatusOperatorAction || overall == preflight.StatusUnsupported {
		return nil, checks, fmt.Errorf("cluster server stage: host preflight blocked with status %q", overall)
	}
	baseline := CheckBundleHostBaseline(facts, resolved.HostBaseline)
	checks = append(checks, baseline)
	if baseline.Status != evidence.StatusPass {
		return nil, checks, errors.New("cluster server stage: host does not match signed bundle baseline")
	}
	if facts.CPUCount < 2 || facts.MemTotalBytes < 4*1024*1024*1024 {
		return nil, checks, errors.New("cluster server stage: each active etcd/server node needs at least 2 CPUs and 4 GiB RAM before profile capacity is evaluated")
	}
	if staged == nil {
		fingerprint, _ := inventory.Fingerprint()
		clusterID := newApplianceInstanceID()
		if !bootstrap {
			clusterID = enrollment.ClusterID
		}
		now := time.Now().UTC()
		staged = &clustertopology.BootstrapState{SchemaVersion: clustertopology.BootstrapStateVersion, Topology: clustertopology.EmbeddedEtcdV1, InventoryFingerprint: fingerprint, ClusterID: clusterID, ApplianceName: identity.Name, ApplianceProfile: resolved.EffectiveProfile, DNSZone: identity.Zone, ReleaseID: resolved.ReleaseID, BundleVersion: resolved.BundleVersion, K3sVersion: resolved.Compatibility.K3sVersion, LocalNode: base.NodeName, Phase: clustertopology.PhasePrepared, CreatedAt: now, UpdatedAt: now}
		if !bootstrap {
			staged.EnrollmentSignerFingerprint = opts.SignerFingerprint
		}
		if err := clustertopology.SaveBootstrapState(stagePath, *staged); err != nil {
			return nil, checks, err
		}
	}
	if renewRelease {
		staged.ReleaseID = resolved.ReleaseID
		staged.BundleVersion = resolved.BundleVersion
		staged.UpdatedAt = time.Now().UTC()
		if err := clustertopology.SaveBootstrapState(stagePath, *staged); err != nil {
			return nil, checks, err
		}
	}
	if staged.Phase == clustertopology.PhaseServerReady || staged.Phase == clustertopology.PhaseJoined || staged.Phase == clustertopology.PhaseFinalized {
		if !signal.Active {
			return nil, checks, errors.New("cluster server stage: recorded server is not active; run cluster repair")
		}
		if currentVersion, err := o.K3s.Version(base.K3sBinaryDestPath); err != nil || currentVersion != resolved.Compatibility.K3sVersion {
			return nil, checks, errors.New("cluster server stage: running K3s version differs from signed release")
		}
		if !bootstrap {
			if err := verifyJoinedServerCA(base.K3sDataDir, enrollment.ClusterCAHash); err != nil {
				return nil, checks, err
			}
		}
		return staged, checks, nil
	}
	if !bootstrap {
		if err := writeJoinToken(opts.ServerTokenFilePath, enrollment.K3sToken); err != nil {
			return nil, checks, err
		}
	}
	if err := o.K3s.WriteConfig(base.K3sConfigPath, config); err != nil {
		return nil, checks, err
	}
	if err := writeImagePullRegistries(o, base, &checks); err != nil {
		return nil, checks, err
	}
	if err := o.K3s.WriteUnit(base.K3sUnitPath, k3s.UnitConfig{BinaryPath: base.K3sBinaryDestPath, ConfigPath: base.K3sConfigPath, Mode: k3s.NodeModeServer}); err != nil {
		return nil, checks, err
	}
	if err := o.K3s.InstallBinary(resolved.K3sBinaryPath, base.K3sBinaryDestPath); err != nil {
		return nil, checks, err
	}
	if err := o.K3s.EnsureKubectlSymlink(base.K3sBinaryDestPath, base.KubectlSymlinkPath); err != nil {
		return nil, checks, err
	}
	if err := o.K3s.EnableAndStart(base.K3sUnitName); err != nil {
		return nil, checks, err
	}
	if !bootstrap {
		if err := verifyJoinedServerCA(base.K3sDataDir, enrollment.ClusterCAHash); err != nil {
			return nil, checks, err
		}
	}
	importer := &images.Importer{Run: o.ImagesRun, Namespace: "k8s.io"}
	if err := importer.WaitReady(ctx, containerdReadyTimeout, containerdReadyPollInterval); err != nil {
		return nil, checks, err
	}
	preloaded, err := importer.PreloadAll(ctx, append(append([]images.Image{}, resolved.K3sImages...), resolved.FilterOCIImages(resolved.OCIImages)...))
	checks = append(checks, preloaded.Checks...)
	if err != nil {
		return nil, checks, err
	}
	if bootstrap {
		signerPath := filepath.Join(filepath.Dir(base.InstalledStatePath), "cluster-enrollment-ed25519.key")
		_, signerFingerprint, err := cluster.LoadOrCreateSigner(signerPath)
		if err != nil {
			return nil, checks, err
		}
		staged.EnrollmentSignerFingerprint = signerFingerprint
		staged.Phase = clustertopology.PhaseServerReady
	} else {
		// A peer is not merely a process that was started: record its immutable
		// Kubernetes UID only after the joining server has actually registered.
		// This lets diagnostics distinguish an operational member from the
		// bootstrap server that still awaits the other two stages/finalization.
		nodeUID, err := waitForEmbeddedEtcdNodeUID(ctx, o.HelmRun, base.KubeconfigPath, base.NodeName)
		if err != nil {
			return nil, checks, err
		}
		staged.NodeUID = nodeUID
		staged.Phase = clustertopology.PhaseJoined
	}
	staged.UpdatedAt = time.Now().UTC()
	if err := clustertopology.SaveBootstrapState(stagePath, *staged); err != nil {
		return nil, checks, err
	}
	return staged, checks, nil
}

func waitForEmbeddedEtcdNodeUID(ctx context.Context, run func(context.Context, string, ...string) (string, error), kubeconfig, nodeName string) (string, error) {
	const timeout = 2 * time.Minute
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		uid, err := cluster.NodeUID(ctx, run, kubeconfig, nodeName)
		if err == nil {
			return uid, nil
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("cluster server stage: wait for joining Kubernetes node: %w", ctx.Err())
		case <-deadline.C:
			return "", fmt.Errorf("cluster server stage: joining Kubernetes node %q did not register within %s: %w", nodeName, timeout, err)
		case <-time.After(time.Second):
		}
	}
}

func verifyJoinedServerCA(dataDir, expectedHash string) error {
	ca, err := os.ReadFile(filepath.Join(dataDir, "server", "tls", "server-ca.crt"))
	if err != nil {
		return fmt.Errorf("cluster server stage: read joined K3s CA: %w", err)
	}
	digest := sha256.Sum256(ca)
	if "sha256:"+hex.EncodeToString(digest[:]) != expectedHash {
		return errors.New("cluster server stage: joined K3s CA differs from signed enrollment")
	}
	return nil
}
