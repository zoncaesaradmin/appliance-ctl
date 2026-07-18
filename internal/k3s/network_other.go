//go:build !linux

package k3s

func deleteNetworkInterface(name string) error {
	return nil
}
