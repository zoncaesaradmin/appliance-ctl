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
// storage: the control-plane pod, the UI sidecar, and every Argo
// workflow pod. Each of those runs as a *different* runAsUser (there is
// deliberately no single "the appliance UID"), but all of them carry
// this GID via fsGroup, which is what actually grants shared access to
// a volume regardless of which UID created a given file in it. This
// value is independently maintained in appliance-code
// (deploy/charts/appliance-control-plane/values.yaml podSecurityContext
// fsGroup, and services/controlplane/internal/workflows/argo/argo.go's
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

	// RegistryDirOwnerUID is the fixed numeric identity for the offline zot
	// registry pod (appliance-registry chart runAsUser).
	RegistryDirOwnerUID = 10003

	// ServiceLogDirMode keeps runtime service logs service-owner writable and
	// host-user readable/traversable (setgid + 0755 → 2755).
	ServiceLogDirMode = os.FileMode(0o755) | os.ModeSetgid

	// RegistryLogDir is the host-visible zot log directory under the shared
	// appliance log tree.
	RegistryLogDir = "/data/zon/logs/zot"
)

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
