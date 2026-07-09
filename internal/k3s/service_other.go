//go:build !linux

package k3s

import "fmt"

// DetectService on non-Linux platforms always reports nothing detected,
// so the dev-machine build and its unit tests still run; the real signal
// only exists on the qualified Linux host baseline.
func DetectService(unitName string) (ServiceSignal, error) {
	return ServiceSignal{}, nil
}

func EnableAndStart(unitName string) error {
	return fmt.Errorf("k3s: service management requires a Linux host with systemd")
}

func Stop(unitName string) error {
	return fmt.Errorf("k3s: service management requires a Linux host with systemd")
}

func Restart(unitName string) error {
	return fmt.Errorf("k3s: service management requires a Linux host with systemd")
}

func DaemonReload() error {
	return fmt.Errorf("k3s: service management requires a Linux host with systemd")
}

func Version(binaryPath string) (string, error) {
	return "", fmt.Errorf("k3s: version detection requires a Linux host")
}
