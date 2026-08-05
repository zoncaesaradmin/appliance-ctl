package hostpackages

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const mdnsServiceName = "avahi-daemon.service"

// InstallSpec selects the installer-owned host package set for the
// current target host. RootDir points at the extracted bundle's
// host-packages directory.
type InstallSpec struct {
	RootDir     string
	OS          string
	OSVersion   string
	Arch        string
	ServiceName string
}

var (
	installedPackageSet = queryInstalledPackages
	installDebArchives  = installPackages
	removeNamedPackages = removePackages
	serviceEnabled      = isServiceEnabled
	serviceActive       = isServiceActive
	enableService       = systemctlEnable
	disableService      = systemctlDisable
	startService        = systemctlStart
	stopService         = systemctlStop
	restartService      = systemctlRestart
	debPackageName      = packageNameFromDeb
)

// ResolvePackageDir maps the supported host baseline to the structured
// bundle directory that contains its offline .deb payloads.
func ResolvePackageDir(rootDir, osName, osVersion, arch string) (string, error) {
	rootDir = strings.TrimSpace(rootDir)
	osName = strings.TrimSpace(osName)
	osVersion = strings.TrimSpace(osVersion)
	arch = strings.TrimSpace(arch)
	if rootDir == "" || osName == "" || osVersion == "" || arch == "" {
		return "", fmt.Errorf("hostpackages: rootDir, os, osVersion, and arch are required")
	}
	dir := filepath.Join(rootDir, osName, osVersion, arch)
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("hostpackages: host package directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("hostpackages: host package path %s is not a directory", dir)
	}
	return dir, nil
}

// Stock daemon units that must not auto-claim host ports or stay enabled after
// dpkg install. appliance-host-agentd owns hostapd/dnsmasq for management Wi-Fi
// AP and avahi for mDNS; day-2 Apply unmasks/starts them when the operator
// enables the feature. Debian stock postinst must not leave them running.
var stockDaemonUnitsToQuiesce = []string{
	"avahi-daemon.service",
	"dnsmasq.service",
	"hostapd.service",
}

// InstallRequiredPackages installs every offline .deb under the bundle
// host-packages tree for this OS/arch (mdns + wifi-ap closures in the
// complete product super-set). Packages are installed at product install /
// upgrade time so day-2 Enable can start services without dpkg/apt.
//
// When ServiceName is empty (normal install path), no feature service is
// enabled or started — only packages land and stock postinst-started units
// (avahi, hostapd, dnsmasq) are stopped/disabled/masked until Admin API
// desired=true.
func InstallRequiredPackages(spec InstallSpec) (func() error, error) {
	serviceName := strings.TrimSpace(spec.ServiceName)
	packageDir, err := ResolvePackageDir(spec.RootDir, spec.OS, spec.OSVersion, spec.Arch)
	if err != nil {
		return nil, err
	}
	debs, err := debArchives(packageDir)
	if err != nil {
		return nil, err
	}
	if len(debs) == 0 {
		return nil, fmt.Errorf("hostpackages: no .deb archives found under %s", packageDir)
	}

	packageNames := make([]string, 0, len(debs))
	for _, deb := range debs {
		name, err := debPackageName(deb)
		if err != nil {
			return nil, err
		}
		packageNames = append(packageNames, name)
	}

	installedBefore, err := installedPackageSet()
	if err != nil {
		return nil, err
	}
	var enabledBefore, activeBefore bool
	if serviceName != "" {
		enabledBefore, err = serviceEnabled(serviceName)
		if err != nil {
			return nil, err
		}
		activeBefore, err = serviceActive(serviceName)
		if err != nil {
			return nil, err
		}
	}

	rollback := func() error {
		var errs []error
		if serviceName != "" {
			if activeBefore {
				if err := startService(serviceName); err != nil {
					errs = append(errs, err)
				}
			} else {
				if err := stopService(serviceName); err != nil {
					errs = append(errs, err)
				}
			}
			if enabledBefore {
				if err := enableService(serviceName); err != nil {
					errs = append(errs, err)
				}
			} else {
				if err := disableService(serviceName); err != nil {
					errs = append(errs, err)
				}
			}
		}

		var newlyInstalled []string
		for _, name := range packageNames {
			if _, ok := installedBefore[name]; !ok {
				newlyInstalled = append(newlyInstalled, name)
			}
		}
		sort.Strings(newlyInstalled)
		if len(newlyInstalled) > 0 {
			if err := removeNamedPackages(newlyInstalled); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}

	if err := installDebArchives(debs); err != nil {
		return nil, err
	}
	// dpkg postinst for dnsmasq/hostapd may enable and start stock units
	// that steal exclusivity of :53 / wireless control from appliance
	// services. Quiesce them after every host-package install.
	if err := QuiesceStockDaemonUnits(); err != nil {
		_ = rollback()
		return nil, err
	}
	if serviceName != "" {
		if err := enableService(serviceName); err != nil {
			_ = rollback()
			return nil, err
		}
		if err := restartService(serviceName); err != nil {
			_ = rollback()
			return nil, err
		}
	}
	return rollback, nil
}

// QuiesceStockDaemonUnits stops, disables, and masks stock avahi/hostapd/dnsmasq
// units so package install does not leave mDNS or Wi-Fi AP "on", and stock
// dnsmasq cannot block appliance-dns. Day-2 enable via host-agent unmasks and
// starts the units it needs. Missing units are ignored.
func QuiesceStockDaemonUnits() error {
	var errs []error
	for _, unit := range stockDaemonUnitsToQuiesce {
		if err := stopService(unit); err != nil && !missingUnitError(err) {
			errs = append(errs, err)
		}
		if err := disableService(unit); err != nil && !missingUnitError(err) {
			errs = append(errs, err)
		}
		if err := maskService(unit); err != nil && !missingUnitError(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// MDNSServiceName is the systemd unit enabled when host mDNS is selected.
const MDNSServiceName = mdnsServiceName

func debArchives(packageDir string) ([]string, error) {
	entries, err := os.ReadDir(packageDir)
	if err != nil {
		return nil, fmt.Errorf("hostpackages: read %s: %w", packageDir, err)
	}
	debs := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".deb") {
			continue
		}
		debs = append(debs, filepath.Join(packageDir, entry.Name()))
	}
	sort.Strings(debs)
	return debs, nil
}

func packageNameFromDeb(path string) (string, error) {
	out, err := runCommand("dpkg-deb", "-f", path, "Package")
	if err != nil {
		return "", fmt.Errorf("hostpackages: read package name from %s: %w", path, err)
	}
	name := strings.TrimSpace(out)
	if name == "" {
		return "", fmt.Errorf("hostpackages: %s did not expose a Package field", path)
	}
	return name, nil
}

func queryInstalledPackages() (map[string]struct{}, error) {
	out, err := runCommand("dpkg-query", "-W", "-f=${Package}\t${Status}\n")
	if err != nil {
		return nil, fmt.Errorf("hostpackages: query installed packages: %w", err)
	}
	packages := map[string]struct{}{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 2 {
			continue
		}
		if strings.TrimSpace(fields[1]) != "install ok installed" {
			continue
		}
		name := strings.TrimSpace(fields[0])
		if name != "" {
			packages[name] = struct{}{}
		}
	}
	return packages, nil
}

func installPackages(paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	args := append([]string{"--install"}, paths...)
	if _, err := runCommand("dpkg", args...); err != nil {
		return fmt.Errorf("hostpackages: install packages: %w", err)
	}
	return nil
}

func removePackages(names []string) error {
	if len(names) == 0 {
		return nil
	}
	args := append([]string{"--remove"}, names...)
	if _, err := runCommand("dpkg", args...); err != nil {
		return fmt.Errorf("hostpackages: remove packages: %w", err)
	}
	return nil
}

func isServiceEnabled(name string) (bool, error) {
	out, err := runCommand("systemctl", "is-enabled", name)
	if err == nil {
		return strings.TrimSpace(out) == "enabled", nil
	}
	text := err.Error()
	if strings.Contains(text, "disabled") || strings.Contains(text, "static") || strings.Contains(text, "indirect") || strings.Contains(text, "not-found") || strings.Contains(text, "No such file") {
		return false, nil
	}
	return false, fmt.Errorf("hostpackages: systemctl is-enabled %s: %w", name, err)
}

func isServiceActive(name string) (bool, error) {
	out, err := runCommand("systemctl", "is-active", name)
	if err == nil {
		return strings.TrimSpace(out) == "active", nil
	}
	text := err.Error()
	if strings.Contains(text, "inactive") || strings.Contains(text, "failed") || strings.Contains(text, "unknown") || strings.Contains(text, "not found") {
		return false, nil
	}
	return false, fmt.Errorf("hostpackages: systemctl is-active %s: %w", name, err)
}

func systemctlEnable(name string) error {
	_, err := runCommand("systemctl", "enable", name)
	if err != nil {
		return fmt.Errorf("hostpackages: enable %s: %w", name, err)
	}
	return nil
}

func systemctlDisable(name string) error {
	_, err := runCommand("systemctl", "disable", name)
	if err != nil && !missingUnitError(err) {
		return fmt.Errorf("hostpackages: disable %s: %w", name, err)
	}
	return nil
}

func systemctlStart(name string) error {
	_, err := runCommand("systemctl", "start", name)
	if err != nil {
		return fmt.Errorf("hostpackages: start %s: %w", name, err)
	}
	return nil
}

func systemctlStop(name string) error {
	_, err := runCommand("systemctl", "stop", name)
	if err != nil && !missingUnitError(err) {
		return fmt.Errorf("hostpackages: stop %s: %w", name, err)
	}
	return nil
}

func systemctlRestart(name string) error {
	_, err := runCommand("systemctl", "restart", name)
	if err != nil {
		return fmt.Errorf("hostpackages: restart %s: %w", name, err)
	}
	return nil
}

func systemctlMask(name string) error {
	_, err := runCommand("systemctl", "mask", name)
	if err != nil && !missingUnitError(err) {
		return fmt.Errorf("hostpackages: mask %s: %w", name, err)
	}
	return nil
}

var maskService = systemctlMask

func missingUnitError(err error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, "not found") ||
		strings.Contains(text, "could not be found") ||
		strings.Contains(text, "not loaded") ||
		strings.Contains(text, "No such file") ||
		strings.Contains(text, "does not exist")
}

func runCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
