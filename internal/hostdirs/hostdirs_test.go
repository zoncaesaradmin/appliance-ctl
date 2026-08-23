package hostdirs_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdirs"
)

type chownCall struct {
	path     string
	uid, gid int
}

func TestEnsureOwnedDir_CreatesMissingDirectoryAndChowns(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "workspaces")
	var calls []chownCall
	fakeChown := func(path string, uid, gid int) error {
		calls = append(calls, chownCall{path, uid, gid})
		return nil
	}

	if err := hostdirs.EnsureOwnedDir(dir, 10001, 10001, 0o770, fakeChown); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("expected directory to be created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("expected a directory")
	}
	if len(calls) != 1 || calls[0] != (chownCall{dir, 10001, 10001}) {
		t.Errorf("expected exactly one chown call for %s to 10001:10001, got %v", dir, calls)
	}
}

// This is the exact production incident this package exists to prevent:
// a directory that already existed with the wrong owner (e.g. created by
// kubelet's hostPath DirectoryOrCreate as root, before this fix shipped)
// must have its ownership and mode corrected, not left alone because it
// already exists.
func TestEnsureOwnedDir_FixesModeOnPreExistingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "workspaces")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	var calls []chownCall
	fakeChown := func(path string, uid, gid int) error {
		calls = append(calls, chownCall{path, uid, gid})
		return nil
	}

	if err := hostdirs.EnsureOwnedDir(dir, 10001, 10001, 0o770, fakeChown); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o770 {
		t.Errorf("expected mode to be corrected to 0770, got %o", info.Mode().Perm())
	}
	if len(calls) != 1 || calls[0] != (chownCall{dir, 10001, 10001}) {
		t.Errorf("expected chown to still run on a pre-existing directory, got %v", calls)
	}
}

func TestEnsureOwnedDir_PropagatesChownFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "workspaces")
	failingChown := func(string, int, int) error {
		return errors.New("operation not permitted")
	}

	if err := hostdirs.EnsureOwnedDir(dir, 10001, 10001, 0o770, failingChown); err == nil {
		t.Fatal("expected chown failure to propagate")
	}
}

func TestServiceLogDirs_FileserverUsesSharedWritableMode(t *testing.T) {
	dirs := hostdirs.ServiceLogDirs(false, true, false, false, false, false)
	var found *hostdirs.OwnedDir
	for i := range dirs {
		if dirs[i].Path == hostdirs.FileserverDir {
			found = &dirs[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected files API directory in ServiceLogDirs when files is enabled")
	}
	if found.UID != hostdirs.ControlPlaneDirOwnerUID || found.GID != hostdirs.ApplianceSharedFSGID {
		t.Fatalf("files API dir ownership = %d:%d, want %d:%d", found.UID, found.GID, hostdirs.ControlPlaneDirOwnerUID, hostdirs.ApplianceSharedFSGID)
	}
	if found.Mode != hostdirs.SharedWritableDirMode {
		t.Fatalf("files API dir mode = %o, want %o (2775 setgid)", found.Mode, hostdirs.SharedWritableDirMode)
	}
	if found.Mode&os.ModeSetgid == 0 || found.Mode.Perm() != 0o775 {
		t.Fatalf("files API dir mode bits = %v, want setgid|0775", found.Mode)
	}
	for _, d := range dirs {
		if d.Path == "/data/zon/logs/fileserver" {
			t.Fatalf("unexpected nginx fileserver log directory in ServiceLogDirs: %#v", d)
		}
	}
}

func TestServiceLogDirs_ArtifactDoesNotImplyFileserver(t *testing.T) {
	dirs := hostdirs.ServiceLogDirs(true, false, false, false, false, false)
	for _, d := range dirs {
		if d.Path == hostdirs.FileserverDir {
			t.Fatalf("artifact-only ServiceLogDirs must not include files API directory: %#v", d)
		}
	}
}

func TestServiceLogDirs_AlwaysIncludesHostAgentLogDirectory(t *testing.T) {
	dirs := hostdirs.ServiceLogDirs(false, false, false, false, false, false)
	for _, dir := range dirs {
		if dir.Path == hostdirs.HostAgentLogDir {
			if dir.UID != hostdirs.HostAgentDirOwnerUID || dir.GID != hostdirs.ApplianceSharedFSGID {
				t.Fatalf("host agent dir ownership = %d:%d, want %d:%d", dir.UID, dir.GID, hostdirs.HostAgentDirOwnerUID, hostdirs.ApplianceSharedFSGID)
			}
			if dir.Mode != hostdirs.ServiceLogDirMode {
				t.Fatalf("host agent dir mode = %o, want %o", dir.Mode, hostdirs.ServiceLogDirMode)
			}
			return
		}
	}
	t.Fatal("expected host agent log directory in ServiceLogDirs")
}

func TestServiceLogDirs_AlwaysIncludesAutomationRuntimeLogDirectory(t *testing.T) {
	dirs := hostdirs.ServiceLogDirs(false, false, false, false, false, false)
	for _, dir := range dirs {
		if dir.Path == hostdirs.AutomationRuntimeLogDir {
			if dir.UID != hostdirs.AutomationRuntimeDirOwnerUID || dir.GID != hostdirs.ApplianceSharedFSGID {
				t.Fatalf("automation runtime dir ownership = %d:%d, want %d:%d", dir.UID, dir.GID, hostdirs.AutomationRuntimeDirOwnerUID, hostdirs.ApplianceSharedFSGID)
			}
			if dir.Mode != hostdirs.ServiceLogDirMode {
				t.Fatalf("automation runtime dir mode = %o, want %o", dir.Mode, hostdirs.ServiceLogDirMode)
			}
			if dir.UID == hostdirs.InferenceDirOwnerUID {
				t.Fatal("automation runtime must not reuse inference UID 10006")
			}
			if dir.UID == hostdirs.VideoDirOwnerUID {
				t.Fatal("automation runtime must not reuse video UID 10008")
			}
			return
		}
	}
	t.Fatal("expected automation runtime log directory in ServiceLogDirs")
}

func TestServiceLogFiles_ArtifactApplicationLogReadable(t *testing.T) {
	if files := hostdirs.ServiceLogFiles(false, true, true, true, true, true); len(files) != 1 || files[0].Path != hostdirs.HostAgentDaemonLog {
		t.Fatalf("expected only host-agent daemon log without artifact capability, got %#v", files)
	}
	files := hostdirs.ServiceLogFiles(true, false, false, false, false, false)
	if len(files) != 2 {
		t.Fatalf("expected host-agent and artifact log files, got %#v", files)
	}
	f := files[1]
	if f.Path != hostdirs.ArtifactServerApplicationLog {
		t.Fatalf("path = %s, want %s", f.Path, hostdirs.ArtifactServerApplicationLog)
	}
	if f.UID != hostdirs.RegistryDirOwnerUID || f.GID != hostdirs.ApplianceSharedFSGID {
		t.Fatalf("ownership = %d:%d, want %d:%d", f.UID, f.GID, hostdirs.RegistryDirOwnerUID, hostdirs.ApplianceSharedFSGID)
	}
	if f.Mode != hostdirs.ServiceLogFileMode || f.Mode.Perm() != 0o644 {
		t.Fatalf("mode = %o, want 0644", f.Mode)
	}
}

func TestEnsureOwnedFile_CreatesAndFixesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "application.log")
	var calls []chownCall
	fakeChown := func(p string, uid, gid int) error {
		calls = append(calls, chownCall{p, uid, gid})
		return nil
	}

	if err := hostdirs.EnsureOwnedFile(path, 10003, 20000, 0o644, fakeChown); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %o, want 0644", info.Mode().Perm())
	}

	if err := os.WriteFile(path, []byte("keep-me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := hostdirs.EnsureOwnedFile(path, 10003, 20000, 0o644, fakeChown); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode after reseed = %o, want 0644", info.Mode().Perm())
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "keep-me\n" {
		t.Fatalf("EnsureOwnedFile must not truncate existing log content, got %q", body)
	}
	if len(calls) != 2 {
		t.Fatalf("expected two chown calls, got %v", calls)
	}
}
