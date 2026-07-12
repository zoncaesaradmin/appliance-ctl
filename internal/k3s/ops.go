package k3s

// Ops is the set of K3s adapter operations the install, upgrade, and
// repair orchestrators need, as injectable function fields (mirroring
// internal/cli.Runner) so tests can supply fakes instead of a real
// systemd host.
type Ops struct {
	DetectService  func(unitName string) (ServiceSignal, error)
	WriteConfig    func(path string, cfg Config) error
	WriteUnit      func(path string, unit UnitConfig) error
	InstallBinary  func(src, dest string) error
	EnableAndStart func(unitName string) error
	Stop           func(unitName string) error
	Restart        func(unitName string) error
	// EnsureKubectlSymlink and RemoveKubectlSymlink manage the
	// "kubectl" convenience symlink to the installed K3s binary (see
	// EnsureKubectlSymlink's doc comment for why zonctl owns this
	// itself rather than relying on K3s's own best-effort behavior).
	EnsureKubectlSymlink func(k3sBinaryPath, kubectlPath string) error
	RemoveKubectlSymlink func(k3sBinaryPath, kubectlPath string) error
	// DaemonReload refreshes systemd's cached unit-file list. Required
	// after removing a unit file (teardown) — DetectService's presence
	// check reads that cache, not the filesystem, so without this a
	// removed unit keeps reporting as detected indefinitely.
	DaemonReload func() error
	// Version reports the K3s version currently installed at binaryPath.
	// Used when adopting an existing cluster to decide whether K3s needs
	// upgrading to the target release's pinned version.
	Version func(binaryPath string) (string, error)
}

// DefaultOps wires Ops to the real package-level functions above.
func DefaultOps() Ops {
	return Ops{
		DetectService:        DetectService,
		WriteConfig:          WriteConfig,
		WriteUnit:            WriteUnit,
		InstallBinary:        InstallBinary,
		EnableAndStart:       EnableAndStart,
		Stop:                 Stop,
		Restart:              Restart,
		DaemonReload:         DaemonReload,
		Version:              Version,
		EnsureKubectlSymlink: EnsureKubectlSymlink,
		RemoveKubectlSymlink: RemoveKubectlSymlink,
	}
}
