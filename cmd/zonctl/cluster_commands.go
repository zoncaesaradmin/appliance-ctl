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

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/cluster"
	"github.com/zoncaesaradmin/appliance-ctl/internal/helm"
	"github.com/zoncaesaradmin/appliance-ctl/internal/install"
	"github.com/zoncaesaradmin/appliance-ctl/internal/nvidia"
	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
	"github.com/zoncaesaradmin/appliance-ctl/internal/runtimeconfig"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

const inferenceRoutingRegistryName = "appliance-inference-routing"

// routingRegistryJSON is deliberately a minimal copy of the inference
// manager's durable wire contract. zonctl owns cluster lifecycle and must be
// able to withdraw a drained node before it is removed; it does not make
// routing decisions or accept an operator-supplied endpoint.
type routingRegistryJSON struct {
	Instances map[string]struct {
		NodeRef string   `json:"nodeRef"`
		Models  []string `json:"models"`
	} `json:"instances"`
	Bindings map[string]json.RawMessage `json:"bindings"`
}

func removeNodeFromRoutingRegistry(raw []byte, nodeName string) ([]byte, bool, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, false, nil
	}
	var registry routingRegistryJSON
	if err := json.Unmarshal(raw, &registry); err != nil {
		return nil, false, fmt.Errorf("decode inference routing registry: %w", err)
	}
	changed := false
	for id, instance := range registry.Instances {
		if instance.NodeRef == nodeName {
			delete(registry.Instances, id)
			changed = true
		}
	}
	if !changed {
		return nil, false, nil
	}
	// Bindings are derived. Remove every binding whose serialized instanceId
	// identifies the withdrawn instance rather than preserving a stale alias.
	for alias, binding := range registry.Bindings {
		var value struct {
			InstanceID string `json:"instanceId"`
		}
		if json.Unmarshal(binding, &value) == nil {
			if _, exists := registry.Instances[value.InstanceID]; !exists {
				delete(registry.Bindings, alias)
			}
		}
	}
	updated, err := json.Marshal(registry)
	if err != nil {
		return nil, false, err
	}
	return updated, true, nil
}

func withdrawNodeRouting(ctx context.Context, nodeName string) error {
	raw, err := cli.Exec(ctx, "kubectl", "--kubeconfig", defaultKubeconfigPath, "-n", "inference", "get", "configmap", inferenceRoutingRegistryName, "-o", "json", "--ignore-not-found")
	if err != nil {
		return fmt.Errorf("read inference routing registry: %w", err)
	}
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var configMap struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &configMap); err != nil {
		return fmt.Errorf("decode inference routing ConfigMap: %w", err)
	}
	updated, changed, err := removeNodeFromRoutingRegistry([]byte(configMap.Data["instances.json"]), nodeName)
	if err != nil || !changed {
		return err
	}
	// JSON Patch's resourceVersion test makes the withdrawal transactional with
	// manager Upsert retries. We fail rather than overwrite a concurrent model
	// publication; the operator can safely rerun the node-removal command.
	patch, err := json.Marshal([]map[string]any{
		{"op": "test", "path": "/metadata/resourceVersion", "value": configMap.Metadata.ResourceVersion},
		{"op": "replace", "path": "/data/instances.json", "value": string(updated)},
	})
	if err != nil {
		return err
	}
	if _, err := cli.Exec(ctx, "kubectl", "--kubeconfig", defaultKubeconfigPath, "-n", "inference", "patch", "configmap", inferenceRoutingRegistryName, "--type=json", "-p", string(patch)); err != nil {
		return fmt.Errorf("withdraw inference routing for node %q: %w", nodeName, err)
	}
	return nil
}

const (
	minimumEnrollmentTTL = time.Minute
	maximumEnrollmentTTL = 24 * time.Hour
)

// These paths are variables solely so the command can be tested without
// touching a real K3s installation. Production always uses K3s's owned data
// directory through their default values.
var (
	clusterServerCAPath = filepath.Join(defaultK3sDataDir, "server", "tls", "server-ca.crt")
	// clusterBootstrapTokenCreate is injectable so the enrollment contract can
	// be tested without a live K3s server. It must create a K3s bootstrap token
	// (not read the reusable server or agent token).
	clusterBootstrapTokenCreate = func(ctx context.Context, ttl, description string) (string, error) {
		return cli.Exec(ctx, defaultK3sBinaryDestPath, "token", "create", "--data-dir", defaultK3sDataDir, "--ttl", ttl, "--description", description)
	}
	clusterServerTokenRead = func() (string, error) {
		data, err := os.ReadFile(filepath.Join(defaultK3sDataDir, "server", "node-token"))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
)

// runClusterEnrollmentCreate creates the only credential a future worker is
// allowed to use to join this appliance. It intentionally does not print the
// enrollment itself: that artifact contains the K3s credential and is written
// as an owner-only file for a separate, offline transfer to the worker.
func runClusterEnrollmentCreate(opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	if strings.TrimSpace(opts.enrollmentOut) == "" {
		return finish(result, "failed", 1, "cluster-enrollment-create: --enrollment-out is required", nil)
	}
	if strings.TrimSpace(opts.controlEndpoint) == "" {
		return finish(result, "failed", 1, "cluster-enrollment-create: --control-endpoint is required", nil)
	}
	if strings.TrimSpace(opts.workerName) == "" {
		return finish(result, "failed", 1, "cluster-enrollment-create: --worker-name is required", nil)
	}
	if opts.workerRole != "worker" && opts.workerRole != "inference" && opts.workerRole != "prime" {
		return finish(result, "failed", 1, "cluster-enrollment-create: --worker-role must be worker, inference, or prime", nil)
	}
	if opts.dryRun {
		return finish(result, "succeeded", 0, fmt.Sprintf("cluster-enrollment-create: would create a %s enrollment for worker %q", opts.workerRole, opts.workerName), nil)
	}
	ttl, err := time.ParseDuration(opts.enrollmentTTL)
	if err != nil || ttl < minimumEnrollmentTTL || ttl > maximumEnrollmentTTL {
		return finish(result, "failed", 1, "cluster-enrollment-create: --enrollment-ttl must be between 1m and 24h", nil)
	}

	statePath := filepath.Join(opts.stateDir, "installed-state.json")
	installed, err := state.Load(statePath)
	if err != nil {
		logger.Error("failed to load installed state", "error", err)
		return finish(result, "failed", 1, "cluster-enrollment-create: "+err.Error(), nil)
	}
	if installed == nil || installed.Cluster == nil {
		return finish(result, "failed", 1, "cluster-enrollment-create: this host has no appliance cluster state", nil)
	}
	if installed.Cluster.ControlPlaneNode != opts.nodeName {
		return finish(result, "failed", 1, "cluster-enrollment-create: this receipt is not the cluster control-plane node", nil)
	}
	if opts.workerName == installed.Cluster.ControlPlaneNode {
		return finish(result, "failed", 1, "cluster-enrollment-create: worker name must differ from the control-plane node", nil)
	}

	// Members use an expiring bootstrap token. Extra primes need the K3s
	// server node-token (wrapped in the enrollment TTL, never printed).
	var token string
	if opts.workerRole == "prime" {
		token, err = clusterServerTokenRead()
		if err != nil {
			return finish(result, "failed", 1, "cluster-enrollment-create: read K3s server token: "+err.Error(), nil)
		}
	} else {
		token, err = clusterBootstrapTokenCreate(context.Background(), opts.enrollmentTTL, "zonctl cluster enrollment for "+opts.workerName)
		if err != nil {
			return finish(result, "failed", 1, "cluster-enrollment-create: create expiring K3s bootstrap token: "+err.Error(), nil)
		}
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return finish(result, "failed", 1, "cluster-enrollment-create: K3s returned an empty bootstrap token", nil)
	}
	ca, err := os.ReadFile(clusterServerCAPath)
	if err != nil {
		return finish(result, "failed", 1, "cluster-enrollment-create: read K3s server CA: "+err.Error(), nil)
	}
	caDigest := sha256.Sum256(ca)
	caHash := "sha256:" + hex.EncodeToString(caDigest[:])

	if current := strings.TrimSpace(installed.Cluster.ControlEndpoint); current != "" && current != strings.TrimSpace(opts.controlEndpoint) {
		return finish(result, "failed", 1, "cluster-enrollment-create: control endpoint differs from the recorded cluster endpoint", nil)
	}
	if current := strings.TrimSpace(installed.Cluster.ClusterCAHash); current != "" && current != caHash {
		return finish(result, "failed", 1, "cluster-enrollment-create: K3s server CA differs from the recorded cluster CA", nil)
	}

	signerPath := filepath.Join(opts.stateDir, "cluster-enrollment-ed25519.key")
	private, signerFingerprint, err := cluster.LoadOrCreateSigner(signerPath)
	if err != nil {
		return finish(result, "failed", 1, "cluster-enrollment-create: load signer: "+err.Error(), nil)
	}
	if current := strings.TrimSpace(installed.Cluster.EnrollmentSignerFingerprint); current != "" && current != signerFingerprint {
		return finish(result, "failed", 1, "cluster-enrollment-create: local signer does not match recorded cluster signer", nil)
	}

	now := time.Now().UTC()
	nonce, err := cluster.NewNonce()
	if err != nil {
		return finish(result, "failed", 1, "cluster-enrollment-create: generate nonce: "+err.Error(), nil)
	}
	enrollment := cluster.Enrollment{
		ClusterID:        installed.Cluster.ID,
		ApplianceName:    installed.ApplianceName,
		ApplianceProfile: installed.ApplianceProfile,
		ControlPlaneNode: installed.Cluster.ControlPlaneNode,
		NodeRole:         opts.workerRole,
		ReleaseID:        installed.InstalledReleaseID,
		ReleaseVersion:   installed.InstalledVersion,
		ControlEndpoint:  strings.TrimSpace(opts.controlEndpoint),
		ClusterCAHash:    caHash,
		ExpectedNodeName: strings.TrimSpace(opts.workerName),
		K3sToken:         token,
		TokenFingerprint: cluster.TokenFingerprint(token),
		IssuedAt:         now,
		ExpiresAt:        now.Add(ttl),
		Nonce:            nonce,
	}
	if err := enrollment.Sign(private); err != nil {
		return finish(result, "failed", 1, "cluster-enrollment-create: sign enrollment: "+err.Error(), nil)
	}
	if err := enrollment.Validate(now, signerFingerprint); err != nil {
		return finish(result, "failed", 1, "cluster-enrollment-create: validate enrollment: "+err.Error(), nil)
	}

	installed.Cluster.Topology = state.TopologyServerWorkers
	installed.Cluster.ControlEndpoint = enrollment.ControlEndpoint
	installed.Cluster.ClusterCAHash = caHash
	installed.Cluster.EnrollmentSignerFingerprint = signerFingerprint
	installed.UpdatedAt = now
	if err := state.Save(statePath, installed); err != nil {
		return finish(result, "failed", 1, "cluster-enrollment-create: save cluster state: "+err.Error(), nil)
	}
	if err := cluster.WriteEnrollment(opts.enrollmentOut, enrollment); err != nil {
		return finish(result, "failed", 1, "cluster-enrollment-create: write enrollment: "+err.Error(), nil)
	}

	data, _ := json.Marshal(map[string]string{
		"clusterId":         enrollment.ClusterID,
		"expectedNodeName":  enrollment.ExpectedNodeName,
		"expiresAt":         enrollment.ExpiresAt.Format(time.RFC3339),
		"signerFingerprint": signerFingerprint,
		"enrollmentPath":    opts.enrollmentOut,
	})
	return finish(result, "succeeded", 0, fmt.Sprintf("cluster enrollment created for worker %q", enrollment.ExpectedNodeName), data)
}

func runClusterJoin(ctx context.Context, opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	if strings.TrimSpace(opts.enrollmentFile) == "" || strings.TrimSpace(opts.clusterSignerFingerprint) == "" {
		return finish(result, "failed", 1, "cluster-join: --enrollment-file and --cluster-signer-fingerprint are required", nil)
	}
	if opts.dryRun {
		return finish(result, "succeeded", 0, "cluster-join: would verify the signed bundle and enroll this host as a K3s agent", nil)
	}
	source, err := resolveInstallSource(opts)
	if err != nil {
		return finish(result, "failed", 1, "cluster-join: "+err.Error(), nil)
	}
	joined, err := install.NewOrchestrator().JoinEnrolledNode(ctx, source, install.JoinWorkerOptions{Options: install.Options{InstalledStatePath: filepath.Join(opts.stateDir, "installed-state.json"), K3sConfigPath: defaultK3sConfigPath, K3sUnitPath: defaultK3sUnitPath, K3sBinaryDestPath: defaultK3sBinaryDestPath, K3sUnitName: defaultK3sUnitName, KubectlSymlinkPath: defaultKubectlSymlinkPath, K3sDataDir: defaultK3sDataDir, K3sCNINetworkDir: defaultK3sCNINetworkDir, K3sCNIInterfaces: append([]string(nil), defaultK3sCNIInterfaces...), NodeName: opts.nodeName, TLSSANs: installTLSSANs(opts), TransactionID: "cluster-join"}, EnrollmentPath: opts.enrollmentFile, SignerFingerprint: opts.clusterSignerFingerprint, K3sAgentTokenPath: "/etc/rancher/k3s/zon-agent-token"})
	if err != nil {
		logger.Error("cluster join failed", "error", err)
		return finish(result, "failed", 1, "cluster-join: "+err.Error(), nil)
	}
	data, _ := json.Marshal(map[string]string{"clusterId": joined.Cluster.ID, "nodeName": opts.nodeName, "nodeRole": joined.Cluster.Nodes[1].Role})
	return finish(result, "succeeded", 0, "cluster join completed; awaiting control-plane registration before scheduling workloads", data)
}

func runClusterWorkerUpgrade(ctx context.Context, opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	if opts.dryRun {
		return finish(result, "succeeded", 0, "cluster-worker-upgrade: would verify the signed bundle and update this K3s agent", nil)
	}
	source, err := resolveInstallSource(opts)
	if err != nil {
		return finish(result, "failed", 1, "cluster-worker-upgrade: "+err.Error(), nil)
	}
	updated, err := install.NewOrchestrator().UpgradeWorker(ctx, source, install.UpgradeWorkerOptions{Options: install.Options{InstalledStatePath: filepath.Join(opts.stateDir, "installed-state.json"), K3sConfigPath: defaultK3sConfigPath, K3sUnitPath: defaultK3sUnitPath, K3sBinaryDestPath: defaultK3sBinaryDestPath, K3sUnitName: defaultK3sUnitName, KubectlSymlinkPath: defaultKubectlSymlinkPath, K3sDataDir: defaultK3sDataDir, NodeName: opts.nodeName, TransactionID: "cluster-worker-upgrade"}, K3sAgentTokenPath: "/etc/rancher/k3s/zon-agent-token"})
	if err != nil {
		logger.Error("worker upgrade failed", "error", err)
		return finish(result, "failed", 1, "cluster-worker-upgrade: "+err.Error(), nil)
	}
	data, _ := json.Marshal(map[string]string{"clusterId": updated.Cluster.ID, "installedVersion": updated.InstalledVersion})
	return finish(result, "succeeded", 0, "cluster worker upgraded; run zonctl verify on the control plane before its upgrade", data)
}

// runClusterNodeRegister is executed only on the control-plane host after a
// worker has joined. Kubernetes is queried first, so state never invents a
// node from an operator-supplied name; then appliance-owned labels make
// scheduling policy explicit without accepting arbitrary selectors.
func runClusterNodeRegister(ctx context.Context, opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	if strings.TrimSpace(opts.workerName) == "" || (opts.workerRole != "worker" && opts.workerRole != "inference" && opts.workerRole != "prime") {
		return finish(result, "failed", 1, "cluster-node-register: --worker-name and --worker-role (worker|inference|prime) are required", nil)
	}
	if opts.dryRun {
		return finish(result, "succeeded", 0, "cluster-node-register: would verify and label the joined node", nil)
	}
	statePath := filepath.Join(opts.stateDir, "installed-state.json")
	installed, err := state.Load(statePath)
	if err != nil || installed == nil || installed.Cluster == nil {
		if err != nil {
			return finish(result, "failed", 1, err.Error(), nil)
		}
		return finish(result, "failed", 1, "cluster-node-register: cluster state is required", nil)
	}
	if installed.Cluster.ControlPlaneNode != opts.nodeName {
		return finish(result, "failed", 1, "cluster-node-register: must run on the control-plane node", nil)
	}
	uid, err := cli.Exec(ctx, "kubectl", "--kubeconfig", defaultKubeconfigPath, "get", "node", opts.workerName, "-o", "jsonpath={.metadata.uid}")
	if err != nil || strings.TrimSpace(uid) == "" {
		return finish(result, "failed", 1, "cluster-node-register: joined Kubernetes node was not found", nil)
	}
	labels := []string{"zon.io/appliance-node=true", "zon.io/role=" + opts.workerRole}
	if opts.workerRole == "inference" {
		labels = append(labels, "zon.io/inference-node=true")
	}
	if opts.workerRole == "prime" {
		labels = []string{"zon.io/appliance-node=true", "zon.io/role=control-plane"}
	}
	args := append([]string{"--kubeconfig", defaultKubeconfigPath, "label", "node", opts.workerName, "--overwrite"}, labels...)
	if _, err := cli.Exec(ctx, "kubectl", args...); err != nil {
		logger.Error("label joined node", "error", err)
		return finish(result, "failed", 1, "cluster-node-register: label node: "+err.Error(), nil)
	}
	role := state.NodeRoleWorker
	if opts.workerRole == "inference" {
		role = state.NodeRoleInference
	}
	if opts.workerRole == "prime" {
		role = state.NodeRoleControlPlane
		installed.Cluster.Topology = state.TopologyMultiServer
	} else if installed.Cluster.Topology != state.TopologyMultiServer {
		installed.Cluster.Topology = state.TopologyServerWorkers
	}
	found := false
	for i := range installed.Cluster.Nodes {
		if installed.Cluster.Nodes[i].Name == opts.workerName {
			installed.Cluster.Nodes[i].ID, installed.Cluster.Nodes[i].NodeUID, installed.Cluster.Nodes[i].Role, installed.Cluster.Nodes[i].Roles = opts.workerName, strings.TrimSpace(uid), role, []string{role}
			found = true
		}
	}
	if !found {
		installed.Cluster.Nodes = append(installed.Cluster.Nodes, state.ClusterNode{ID: opts.workerName, NodeUID: strings.TrimSpace(uid), Name: opts.workerName, Role: role, Roles: []string{role}})
	}
	installed.UpdatedAt = time.Now().UTC()
	if err := state.Save(statePath, installed); err != nil {
		return finish(result, "failed", 1, "cluster-node-register: save state: "+err.Error(), nil)
	}
	data, _ := json.Marshal(map[string]string{"nodeName": opts.workerName, "nodeUID": strings.TrimSpace(uid), "nodeRole": role})
	return finish(result, "succeeded", 0, "cluster node registered and labeled", data)
}

// runClusterNodeRemove drains a worker before deleting its K3s node and its
// authoritative inventory entry. It deliberately cannot remove the fixed
// initial control plane; HA control-plane replacement is a later operation.
func runClusterNodeRemove(ctx context.Context, opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	if strings.TrimSpace(opts.workerName) == "" || opts.confirm != opts.workerName {
		return finish(result, "failed", 1, "cluster-node-remove: --worker-name and --confirm <worker-name> are required", nil)
	}
	if opts.dryRun {
		return finish(result, "succeeded", 0, "cluster-node-remove: would drain and remove the worker", nil)
	}
	statePath := filepath.Join(opts.stateDir, "installed-state.json")
	installed, err := state.Load(statePath)
	if err != nil || installed == nil || installed.Cluster == nil {
		if err != nil {
			return finish(result, "failed", 1, err.Error(), nil)
		}
		return finish(result, "failed", 1, "cluster-node-remove: cluster state is required", nil)
	}
	if installed.Cluster.ControlPlaneNode != opts.nodeName {
		return finish(result, "failed", 1, "cluster-node-remove: must run on the control-plane node", nil)
	}
	if opts.workerName == installed.Cluster.ControlPlaneNode {
		return finish(result, "failed", 1, "cluster-node-remove: removing the control-plane node is not supported", nil)
	}
	found := false
	nodeUID := ""
	for _, node := range installed.Cluster.Nodes {
		if node.Name == opts.workerName {
			found = true
			nodeUID = strings.TrimSpace(node.NodeUID)
			break
		}
	}
	if !found {
		return finish(result, "failed", 1, "cluster-node-remove: worker is not in cluster inventory", nil)
	}
	if _, err := cli.Exec(ctx, "kubectl", "--kubeconfig", defaultKubeconfigPath, "cordon", opts.workerName); err != nil {
		return finish(result, "failed", 1, "cluster-node-remove: cordon worker: "+err.Error(), nil)
	}
	if nodeUID == "" {
		nodeUID = opts.workerName // legacy node receipt fallback
	}
	if err := withdrawNodeRouting(ctx, nodeUID); err != nil {
		return finish(result, "failed", 1, "cluster-node-remove: "+err.Error(), nil)
	}
	if _, err := cli.Exec(ctx, "kubectl", "--kubeconfig", defaultKubeconfigPath, "drain", opts.workerName, "--ignore-daemonsets", "--delete-emptydir-data", "--timeout=5m"); err != nil {
		logger.Error("drain worker", "error", err)
		return finish(result, "failed", 1, "cluster-node-remove: drain worker: "+err.Error(), nil)
	}
	if release, err := productconfig.InferenceNodeReleaseName(opts.workerName); err != nil {
		return finish(result, "failed", 1, "cluster-node-remove: "+err.Error(), nil)
	} else if err := (&helm.Applier{Run: cli.Exec, Kubeconfig: defaultKubeconfigPath}).UninstallInNamespace(ctx, release, "inference"); err != nil {
		return finish(result, "failed", 1, "cluster-node-remove: remove node inference release: "+err.Error(), nil)
	}
	if _, err := cli.Exec(ctx, "kubectl", "--kubeconfig", defaultKubeconfigPath, "delete", "node", opts.workerName); err != nil {
		return finish(result, "failed", 1, "cluster-node-remove: delete node: "+err.Error(), nil)
	}
	kept := installed.Cluster.Nodes[:0]
	for _, node := range installed.Cluster.Nodes {
		if node.Name != opts.workerName {
			kept = append(kept, node)
		}
	}
	installed.Cluster.Nodes = kept
	installed.UpdatedAt = time.Now().UTC()
	if err := state.Save(statePath, installed); err != nil {
		return finish(result, "failed", 1, "cluster-node-remove: save cluster state: "+err.Error(), nil)
	}
	data, _ := json.Marshal(map[string]string{"nodeName": opts.workerName})
	return finish(result, "succeeded", 0, "cluster worker drained and removed", data)
}

// runClusterInferenceDeploy creates or reconciles the isolated manager release
// for a registered inference worker. It consumes the same signed bundle input
// as install; no chart/image is fetched from a network or accepted from flags.
func runClusterInferenceDeploy(ctx context.Context, opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	if strings.TrimSpace(opts.workerName) == "" {
		return finish(result, "failed", 1, "cluster-inference-deploy: --worker-name is required", nil)
	}
	if opts.dryRun {
		return finish(result, "succeeded", 0, "cluster-inference-deploy: would reconcile the node-bound inference release", nil)
	}
	installed, err := state.Load(filepath.Join(opts.stateDir, "installed-state.json"))
	if err != nil || installed == nil || installed.Cluster == nil {
		return finish(result, "failed", 1, "cluster-inference-deploy: cluster state is required", nil)
	}
	if installed.Cluster.ControlPlaneNode != opts.nodeName {
		return finish(result, "failed", 1, "cluster-inference-deploy: must run on the control-plane node", nil)
	}
	nodeUID := ""
	for _, node := range installed.Cluster.Nodes {
		if node.Name == opts.workerName && node.Role == state.NodeRoleInference {
			nodeUID = node.NodeUID
		}
	}
	if strings.TrimSpace(nodeUID) == "" {
		return finish(result, "failed", 1, "cluster-inference-deploy: worker is not a registered inference node", nil)
	}
	observedUID, err := cli.Exec(ctx, "kubectl", "--kubeconfig", defaultKubeconfigPath, "get", "node", opts.workerName, "-o", "jsonpath={.metadata.uid}")
	if err != nil || strings.TrimSpace(observedUID) == "" {
		return finish(result, "failed", 1, "cluster-inference-deploy: registered Kubernetes node was not found", nil)
	}
	if err := validateRegisteredNodeUID(nodeUID, observedUID); err != nil {
		return finish(result, "failed", 1, "cluster-inference-deploy: "+err.Error(), nil)
	}
	_, resolved, _, err := resolveVerifiedInstallSource(ctx, opts, installed.ApplianceProfile)
	if err != nil || resolved.ReleaseID != installed.InstalledReleaseID || resolved.BundleVersion != installed.InstalledVersion {
		return finish(result, "failed", 1, "cluster-inference-deploy: signed bundle does not match installed cluster release", nil)
	}
	runtime, ok := resolved.Runtimes["inference"]
	if !ok || resolved.InferenceChartPath == "" {
		return finish(result, "failed", 1, "cluster-inference-deploy: signed bundle has no inference runtime", nil)
	}
	if runtimeconfig.RequiresGPU(runtime) {
		if err := nvidia.EnsureRuntimeClass(ctx, cli.Exec, defaultKubeconfigPath); err != nil {
			return finish(result, "failed", 1, "cluster-inference-deploy: configure NVIDIA RuntimeClass: "+err.Error(), nil)
		}
	}
	values, cleanup, err := productconfig.PrepareNodeInferenceValuesFile(filepath.Dir(resolved.ConfigurationPath), resolved.InferenceImageReference, resolved.InferenceManagerImageReference, runtime, opts.workerName, nodeUID)
	if err != nil {
		return finish(result, "failed", 1, "cluster-inference-deploy: "+err.Error(), nil)
	}
	defer cleanup()
	release, err := productconfig.InferenceNodeReleaseName(opts.workerName)
	if err != nil {
		return finish(result, "failed", 1, "cluster-inference-deploy: "+err.Error(), nil)
	}
	check, err := (&helm.Applier{Run: cli.Exec, Kubeconfig: defaultKubeconfigPath}).InstallOrUpgrade(ctx, helm.ChartRelease{Name: release, ChartPath: resolved.InferenceChartPath, Namespace: "inference", ValuesPath: values, NamespaceLabels: helm.RestrictedNamespaceLabels()})
	if err != nil {
		logger.Error("deploy inference node", "node", opts.workerName, "error", err)
		return finish(result, "failed", 1, "cluster-inference-deploy: "+err.Error(), nil)
	}
	now := time.Now().UTC()
	installed.LastOperation = state.Operation{Type: "cluster-inference-deploy", Status: "completed", TransactionID: "cluster-inference-deploy", StartedAt: now, CompletedAt: &now}
	installed.UpdatedAt = now
	if err := state.Save(filepath.Join(opts.stateDir, "installed-state.json"), installed); err != nil {
		return finish(result, "failed", 1, "cluster-inference-deploy: persist lifecycle state: "+err.Error(), nil)
	}
	data, _ := json.Marshal(map[string]any{"nodeName": opts.workerName, "release": release, "check": check.ID})
	return finish(result, "succeeded", 0, "node-bound inference release reconciled", data)
}

func validateRegisteredNodeUID(expected, observed string) error {
	if strings.TrimSpace(expected) == "" || strings.TrimSpace(observed) == "" || strings.TrimSpace(expected) != strings.TrimSpace(observed) {
		return fmt.Errorf("Kubernetes node UID does not match registered cluster inventory")
	}
	return nil
}
