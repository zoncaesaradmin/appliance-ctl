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
	// Version reports the K3s version currently installed at binaryPath.
	// Used when adopting an existing cluster to decide whether K3s needs
	// upgrading to the target release's pinned version.
	Version func(binaryPath string) (string, error)
}

// DefaultOps wires Ops to the real package-level functions above.
func DefaultOps() Ops {
	return Ops{
		DetectService:  DetectService,
		WriteConfig:    WriteConfig,
		WriteUnit:      WriteUnit,
		InstallBinary:  InstallBinary,
		EnableAndStart: EnableAndStart,
		Stop:           Stop,
		Restart:        Restart,
		Version:        Version,
	}
}
