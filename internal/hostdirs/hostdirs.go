// Package hostdirs creates and owns the appliance-managed host
// directories that back static hostPath PersistentVolumes — directories
// zonctl must prepare itself rather than rely on Kubernetes to prepare
// correctly. Kubernetes' automatic fsGroup ownership recursion at mount
// time is designed around volumes Kubernetes itself provisions
// (emptyDir, CSI-backed PVs, K3s's own local-path-provisioner PVs); it
// is not reliably applied to a static hostPath volume pointed at a
// directory Kubernetes didn't create, which is exactly the workspace
// storage volume's shape. So the appliance seeds correct ownership
// itself, once, deterministically, instead of discovering the gap as a
// "Permission denied" inside a workflow pod.
package hostdirs

import (
	"fmt"
	"os"
)

// ApplianceSharedFSGID is the one numeric group ID shared across every
// appliance pod type that needs to read/write appliance-managed host
// storage: the control-plane pod, the UI sidecar, and every
// workflow pod. Each of those runs as a *different* runAsUser (there is
// deliberately no single "the appliance UID"), but all of them carry
// this GID via fsGroup, which is what actually grants shared access to
// a volume regardless of which UID created a given file in it. This
// value is independently maintained in appliance-code
// (deploy/charts/appliance-control-plane/values.yaml podSecurityContext
// fsGroup, and services/controlplane/internal/workflows/engine/engine.go's
// sharedFSGID) — if it changes there, it must change here too.
//
// ApplianceDirOwnerUID is an arbitrary fixed owner for directories this
// package creates. It doesn't need to match any pod's runAsUser — group
// membership via fsGroup is what grants access — so root is used simply
// because it's always guaranteed to exist and never in conflict with an
// appliance pod's own UID.
const (
	ApplianceDirOwnerUID = 0
	ApplianceSharedFSGID = 20000

	// ControlPlaneDirOwnerUID is the fixed numeric identity for the main
	// control-plane pod.
	ControlPlaneDirOwnerUID = 10001
	// UIDirOwnerUID is the fixed numeric identity for the UI pod.
	UIDirOwnerUID = 10002
	// RegistryDirOwnerUID is the fixed numeric identity for the offline
	// artifact server registry pod (appliance-registry chart runAsUser).
	RegistryDirOwnerUID = 10003
	// WorkflowControllerDirOwnerUID is the fixed numeric identity for the
	// workflow-controller pod.
	WorkflowControllerDirOwnerUID = 65532
	// DNSDirOwnerUID is the fixed numeric identity for the offline
	// LAN DNS (CoreDNS) pod (appliance-dns chart runAsUser). The wrapper
	// image tees CoreDNS stdout/stderr into /data/zon/logs/dns.
	DNSDirOwnerUID = 10004
	// HostAgentDirOwnerUID is the fixed numeric identity for the in-cluster
	// appliance host agent pod.
	HostAgentDirOwnerUID = 10005
	// InferenceDirOwnerUID is the fixed numeric identity for the offline
	// inference runtime pod (appliance-inference chart runAsUser). Distinct
	// from HostAgentDirOwnerUID even though both are non-root appliance
	// identities — never reuse service UIDs across components.
	InferenceDirOwnerUID = 10006
	// AutomationRuntimeDirOwnerUID is the fixed numeric identity for the
	// automation-runtime pod (metadata-bundle + DSL execution). Distinct from
	// InferenceDirOwnerUID — never reuse service UIDs across components.
	AutomationRuntimeDirOwnerUID = 10007
	// BlobStorageDirOwnerUID is the fixed numeric identity for the local
	// S3-compatible blob-storage service.
	BlobStorageDirOwnerUID = 10009

	// ServiceLogDirMode keeps runtime service logs service-owner writable and
	// host-user readable/traversable (setgid + 0755 → 2755).
	ServiceLogDirMode = os.FileMode(0o755) | os.ModeSetgid
	// ServiceLogFileMode is the operator-facing mode for files under service
	// log directories (owner write, world read). Upstream tools such as zot may
	// create application.log as 0600; zonctl reseeds 0644 so host users can
	// `tail` without sudo.
	ServiceLogFileMode = os.FileMode(0o644)
	// SharedWritableDirMode is setgid + group-writable + host-readable (2775)
	// for operator-visible host paths that the control-plane writes via the
	// authenticated files API (runAsUser 10001, fsGroup 20000). Host users
	// can inspect with ls/cat like service log dirs. Private shared storage
	// that must stay host-opaque should keep 2770 instead.
	SharedWritableDirMode = os.FileMode(0o775) | os.ModeSetgid

	// APIServerLogDir is the host-visible api-server (control-plane) log
	// directory under the shared appliance log tree.
	APIServerLogDir = "/data/zon/logs/api-server"
	// UILogDir is the host-visible UI log directory under the shared appliance
	// log tree.
	UILogDir = "/data/zon/logs/ui"
	// ArtifactServerLogDir is the host-visible artifact server log
	// directory under the shared appliance log tree.
	ArtifactServerLogDir = "/data/zon/logs/artifactserver"
	// ArtifactServerApplicationLog is the artifact server application log
	// file under ArtifactServerLogDir. Upstream zot creates this as 0600;
	// zonctl reseeds it to ServiceLogFileMode so host operators can read it.
	ArtifactServerApplicationLog = ArtifactServerLogDir + "/application.log"
	// WorkflowControllerLogDir is the host-visible workflow-controller log
	// directory under the shared appliance log tree.
	WorkflowControllerLogDir = "/data/zon/logs/workflow-controller"
	// DNSLogDir is the host-visible LAN DNS (CoreDNS) log directory under
	// the shared appliance log tree.
	DNSLogDir = "/data/zon/logs/dns"
	// InferenceLogDir is the host-visible inference runtime log directory
	// under the shared appliance log tree.
	InferenceLogDir = "/data/zon/logs/inference"
	// AutomationRuntimeLogDir is the host-visible automation-runtime log
	// directory under the shared appliance log tree.
	AutomationRuntimeLogDir = "/data/zon/logs/automation-runtime"
	// InferenceModelsDir is the host-visible model-weight tree mounted into
	// the inference runtime at /models (filled by zonctl models-import).
	InferenceModelsDir = "/data/zon/inference/models"
	// BlobStorageDir backs the foundation blob-storage pod. Consumers use its
	// S3 API and never receive this host path.
	BlobStorageDir = "/data/zon/blob-storage"
	// HostAgentLogDir is the host-visible appliance host agent log directory
	// under the shared appliance log tree.
	HostAgentLogDir = "/data/zon/logs/host-agent"
	// HostAgentDaemonLog is the host-side daemon log file under HostAgentLogDir.
	HostAgentDaemonLog = HostAgentLogDir + "/host-agentd.log"
	// MetadataBundlesDir is the host-visible tree of extracted appliance policy
	// bundles mounted into the control-plane pod at
	// {persistence.dataDir}/metadata-bundles.
	MetadataBundlesDir = "/data/zon/metadata-bundles"
)

// OwnedDir describes one appliance-managed host directory whose ownership and
// mode zonctl must seed before Kubernetes mounts it into a pod.
type OwnedDir struct {
	CheckID string
	Path    string
	UID     int
	GID     int
	Mode    os.FileMode
}

// ServiceLogDirs returns the host-visible log directories the selected
// capability set requires. Control-plane, UI, and automation runtime always
// exist; host-agent, registry logs, workflow-controller, DNS, and
// inference logs are added only when those capabilities are enabled.
// The files capability stores objects in foundation blob-storage, so it does
// not add a dedicated host directory here.
func ServiceLogDirs(includeArtifact, includeFiles, includeWorkflows, includeDNS, includeInference bool, includeHost ...bool) []OwnedDir {
	_ = includeFiles
	hostEnabled := len(includeHost) == 0 || includeHost[0]
	dirs := []OwnedDir{
		{
			CheckID: "api-server-log-directory-owned",
			Path:    APIServerLogDir,
			UID:     ControlPlaneDirOwnerUID,
			GID:     ApplianceSharedFSGID,
			Mode:    ServiceLogDirMode,
		},
		{
			CheckID: "ui-log-directory-owned",
			Path:    UILogDir,
			UID:     UIDirOwnerUID,
			GID:     ApplianceSharedFSGID,
			Mode:    ServiceLogDirMode,
		},
		{
			CheckID: "automation-runtime-log-directory-owned",
			Path:    AutomationRuntimeLogDir,
			UID:     AutomationRuntimeDirOwnerUID,
			GID:     ApplianceSharedFSGID,
			Mode:    ServiceLogDirMode,
		},
	}
	if hostEnabled {
		dirs = append(dirs, OwnedDir{
			CheckID: "host-agent-log-directory-owned",
			Path:    HostAgentLogDir,
			UID:     HostAgentDirOwnerUID,
			GID:     ApplianceSharedFSGID,
			Mode:    ServiceLogDirMode,
		})
	}
	if includeArtifact {
		dirs = append(dirs, OwnedDir{
			CheckID: "artifactserver-log-directory-owned",
			Path:    ArtifactServerLogDir,
			UID:     RegistryDirOwnerUID,
			GID:     ApplianceSharedFSGID,
			Mode:    ServiceLogDirMode,
		})
	}
	if includeWorkflows {
		dirs = append(dirs, OwnedDir{
			CheckID: "workflow-controller-log-directory-owned",
			Path:    WorkflowControllerLogDir,
			UID:     WorkflowControllerDirOwnerUID,
			GID:     ApplianceSharedFSGID,
			Mode:    ServiceLogDirMode,
		})
	}
	if includeDNS {
		dirs = append(dirs, OwnedDir{
			CheckID: "dns-log-directory-owned",
			Path:    DNSLogDir,
			UID:     DNSDirOwnerUID,
			GID:     ApplianceSharedFSGID,
			Mode:    ServiceLogDirMode,
		})
	}
	if includeInference {
		dirs = append(dirs, OwnedDir{
			CheckID: "inference-log-directory-owned",
			Path:    InferenceLogDir,
			UID:     InferenceDirOwnerUID,
			GID:     ApplianceSharedFSGID,
			Mode:    ServiceLogDirMode,
		})
	}
	return dirs
}

// ServiceLogFiles returns host-visible log files that zonctl must seed (or
// re-chmod) in addition to ServiceLogDirs. Today this is only the artifact
// server's application.log, which upstream creates as 0600.
func ServiceLogFiles(includeArtifact, _, _, _, _ bool, includeHost ...bool) []OwnedDir {
	hostEnabled := len(includeHost) == 0 || includeHost[0]
	files := []OwnedDir(nil)
	if hostEnabled {
		files = append(files, OwnedDir{
			CheckID: "host-agent-daemon-log-readable",
			Path:    HostAgentDaemonLog,
			UID:     0,
			GID:     ApplianceSharedFSGID,
			Mode:    ServiceLogFileMode,
		})
	}
	if !includeArtifact {
		return files
	}
	files = append(files, OwnedDir{
		CheckID: "artifactserver-application-log-readable",
		Path:    ArtifactServerApplicationLog,
		UID:     RegistryDirOwnerUID,
		GID:     ApplianceSharedFSGID,
		Mode:    ServiceLogFileMode,
	})
	return files
}

// WorkspaceDirMode is deliberately world-readable and world-writable
// (not just group-writable via ApplianceSharedFSGID). An operator needs
// to be able to inspect — and, at their own risk, edit — cloned
// workspace content from a normal host login, not just from a process
// that happens to carry the shared fsGroup. This is a real widening of
// who can touch this one directory tree; it's confined to workspace
// storage and isn't the default posture for any other appliance-managed
// path.
//
// os.ModeSetgid is layered on top so every file or directory created
// under this tree — by a workflow pod, by an operator, or by an
// external rsync/scp push from a different device entirely — inherits
// group ApplianceSharedFSGID automatically, regardless of the creating
// process's own primary group. (Note: os.FileMode's setgid bit is the
// distinct os.ModeSetgid flag, not the raw octal 02000 Unix mode_t
// uses — combining it with plain octal here would silently do nothing.)
// The 0777 permission bits alone only govern who may create entries in
// the directory itself; they say nothing about the group ownership new
// entries get, and the appliance has no control over the umask of a
// remote rsync/scp session. Setgid is the one lever available on the
// receiving end to keep new content consistently group-accessible no
// matter which account wrote it.
const WorkspaceDirMode = os.FileMode(0o777) | os.ModeSetgid

// ChownFunc matches os.Chown's signature so tests can inject a fake
// instead of requiring the test process to run as root (arbitrary chown
// targets require root/CAP_CHOWN).
type ChownFunc func(path string, uid, gid int) error

// EnsureOwnedDir creates path (and any missing parents) if needed, and
// makes sure it is owned uid:gid with mode perm — fixing ownership and
// mode even if the directory already existed with the wrong owner, since
// that is exactly the state a host affected by the fsGroup gap this
// package exists to close is in.
func EnsureOwnedDir(path string, uid, gid int, perm os.FileMode, chown ChownFunc) error {
	if err := os.MkdirAll(path, perm); err != nil {
		return fmt.Errorf("hostdirs: create %s: %w", path, err)
	}
	if err := os.Chmod(path, perm); err != nil {
		return fmt.Errorf("hostdirs: chmod %s: %w", path, err)
	}
	if err := chown(path, uid, gid); err != nil {
		return fmt.Errorf("hostdirs: chown %s to %d:%d: %w", path, uid, gid, err)
	}
	return nil
}

// EnsureOwnedFile creates an empty file at path if missing, then forces
// ownership and mode. Used for operator-facing log files that an upstream
// process may create with a too-restrictive mode (for example zot 0600).
func EnsureOwnedFile(path string, uid, gid int, perm os.FileMode, chown ChownFunc) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, perm)
	if err != nil {
		return fmt.Errorf("hostdirs: create %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("hostdirs: close %s: %w", path, err)
	}
	if err := os.Chmod(path, perm); err != nil {
		return fmt.Errorf("hostdirs: chmod %s: %w", path, err)
	}
	if err := chown(path, uid, gid); err != nil {
		return fmt.Errorf("hostdirs: chown %s to %d:%d: %w", path, uid, gid, err)
	}
	return nil
}
