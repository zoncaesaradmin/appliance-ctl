//go:build !linux

package k3s

func killLeftoverContainerdShims() error {
	return nil
}

func killLeftoverKubePodProcesses() error {
	return nil
}
