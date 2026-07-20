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
)

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
