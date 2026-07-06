//go:build !linux

package host

import (
	"os"
	"runtime"
	"time"
)

// Detect on non-Linux platforms returns only the OS-agnostic signals
// (architecture, CPU count, hostname) so the preflight checks and their
// unit tests can run on a developer workstation. Linux-only signals
// (cgroup version, kernel release, filesystem type, etc.) are left at
// their zero value; the corresponding checks correctly report the host
// as unsupported rather than guessing.
func Detect(opts Options) (Facts, error) {
	f := Facts{
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		CPUCount:      runtime.NumCPU(),
		DataDir:       opts.DataDir,
		RequiredPorts: opts.RequiredPorts,
		PortsInUse:    map[int]string{},
		DetectedAt:    time.Now().UTC(),
	}

	if hostname, err := os.Hostname(); err == nil {
		f.Hostname = hostname
	}

	return f, nil
}
