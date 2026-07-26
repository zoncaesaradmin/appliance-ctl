//go:build !linux

package hostdns

func releaseOrphanCoreDNSListeners() (bool, error) {
	return false, nil
}
