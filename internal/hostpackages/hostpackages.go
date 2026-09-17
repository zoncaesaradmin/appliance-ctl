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
const mdnsSocketName = "avahi-daemon.socket"

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
	unmaskService       = systemctlUnmask
	debPackageName      = packageNameFromDeb
	stopUnitGroup       = systemctlStopUnitGroup
	unitInactive        = isUnitInactive
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

// Stock host daemons are managed as two independent groups:
//
//  1. Conflict group (dnsmasq, hostapd): always quiesced after package install
//     and before appliance-dns. They steal :53 / radio from appliance-owned
//     services. day-2 Wi-Fi AP apply unmasks/starts them when needed.
//
//  2. mDNS group (avahi-daemon.socket + avahi-daemon.service): interdependent
//     (service Requires= socket on Ubuntu). Treated as one atomic unit group.
//     When lan-discovery is selected, leave them running / ensure-running —
//     never stop+mask then restart mid-install (that races with socket
//     activation and cancels jobs). When lan-discovery is off, quiesce the
//     whole group so stock postinst does not leave mDNS claiming the LAN.
//
// Host vendor drop-ins (e.g. nvidia-spark Avahi config) and existing
// /etc/avahi/services entries are left untouched here; appliance mDNS
// identity is layered later by host-agentd.
var (
	conflictDaemonUnits = []string{
		"dnsmasq.service",
		"hostapd.service",
	}
	mdnsDaemonUnits = []string{
		mdnsSocketName,
		mdnsServiceName,
	}
)

// companionUnitsFor returns units that must move with a selected feature
// service (unmask/start or stop/mask together).
func companionUnitsFor(serviceName string) []string {
	switch strings.TrimSpace(serviceName) {
	case mdnsServiceName:
		return []string{mdnsSocketName}
	default:
		return nil
	}
}

func unitGroupForService(serviceName string) []string {
	serviceName = strings.TrimSpace(serviceName)
	comps := companionUnitsFor(serviceName)
	if len(comps) == 0 {
		if serviceName == "" {
			return nil
		}
		return []string{serviceName}
	}
	out := make([]string, 0, len(comps)+1)
	out = append(out, comps...)
	out = append(out, serviceName)
	return out
}

// InstallRequiredPackages installs missing offline .deb files under the bundle
// host-packages tree for this OS/arch (mdns + wifi-client + wifi-ap closures in the
// complete product super-set). Packages already install-ok on the host are
// skipped so reinstall/e2e cycles do not re-run dpkg over libc/apt and similar
// transitive closures (slow, and previously hit a short command timeout).
// Packages are installed at product install / upgrade time so day-2 Enable can
// start services without dpkg/apt.
//
// When ServiceName names the mDNS unit (lan-discovery), conflict daemons are
// quiesced but Avahi is left alone / ensured running — prior host mDNS state
// and vendor config stay intact. When ServiceName is empty, Avahi is quiesced
// with the conflict group.
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

	var toInstall []string
	for i, deb := range debs {
		if _, ok := installedBefore[packageNames[i]]; ok {
			continue
		}
		toInstall = append(toInstall, deb)
	}

	rollback := func() error {
		var errs []error
		if serviceName != "" {
			if activeBefore {
				if err := EnsureFeatureUnitsRunning(serviceName); err != nil {
					errs = append(errs, err)
				}
			} else {
				if err := ensureUnitsQuiesced(unitGroupForService(serviceName)...); err != nil {
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

	if err := installDebArchives(toInstall); err != nil {
		return nil, err
	}
	// Always quiet Wi-Fi AP / stock dnsmasq — they conflict with appliance-dns
	// and management Wi-Fi ownership regardless of lan-discovery.
	if err := QuiesceConflictingHostDaemons(); err != nil {
		_ = rollback()
		return nil, err
	}
	switch serviceName {
	case "":
		if err := QuiesceMDNSUnits(); err != nil {
			_ = rollback()
			return nil, err
		}
	case mdnsServiceName:
		if err := EnsureFeatureUnitsRunning(serviceName); err != nil {
			_ = rollback()
			return nil, err
		}
	default:
		if err := EnsureFeatureUnitsRunning(serviceName); err != nil {
			_ = rollback()
			return nil, err
		}
	}
	return rollback, nil
}

// QuiesceConflictingHostDaemons stops/disables/masks stock dnsmasq and hostapd
// so they cannot claim :53 or the radio. Safe to call while lan-discovery mDNS
// must stay up — Avahi is not touched.
func QuiesceConflictingHostDaemons() error {
	return ensureUnitsQuiesced(conflictDaemonUnits...)
}

// QuiesceMDNSUnits stops/disables/masks the Avahi socket+service group when
// lan-discovery is not selected. Prefer QuiesceConflictingHostDaemons when
// mDNS must remain available.
func QuiesceMDNSUnits() error {
	return ensureUnitsQuiesced(mdnsDaemonUnits...)
}

// QuiesceStockDaemonUnits quiesces every stock host daemon (conflict + mDNS).
// Prefer the specific helpers when mDNS may need to stay running.
func QuiesceStockDaemonUnits() error {
	return errors.Join(QuiesceConflictingHostDaemons(), QuiesceMDNSUnits())
}

// EnsureFeatureUnitsRunning brings a selected feature service (and Required
// companions) to active without a stop/mask dance. If the service is already
// active, it is left alone so vendor config and existing mDNS publications
// survive. Missing units are ignored only when the whole group is absent.
func EnsureFeatureUnitsRunning(serviceName string) error {
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		return fmt.Errorf("hostpackages: EnsureFeatureUnitsRunning requires a service name")
	}
	group := unitGroupForService(serviceName)
	for _, unit := range group {
		if err := unmaskService(unit); err != nil && !missingUnitError(err) {
			return err
		}
	}
	active, err := serviceActive(serviceName)
	if err != nil {
		return err
	}
	if active {
		return nil
	}
	if err := enableService(serviceName); err != nil && !missingUnitError(err) {
		return err
	}
	if err := startService(serviceName); err != nil && !missingUnitError(err) {
		// Start can race; accept success if the unit became active anyway.
		active, activeErr := serviceActive(serviceName)
		if activeErr == nil && active {
			return nil
		}
		return err
	}
	active, err = serviceActive(serviceName)
	if err != nil {
		return err
	}
	if !active {
		return fmt.Errorf("hostpackages: %s did not become active", serviceName)
	}
	return nil
}

// ensureUnitsQuiesced drives units to inactive+masked. Stop is issued once for
// the whole group with --job-mode=replace so interdependent socket/service
// pairs cannot cancel each other. Success is defined by final state, not by
// individual systemctl exit codes ("Job … canceled" is OK if units end idle).
func ensureUnitsQuiesced(units ...string) error {
	if len(units) == 0 {
		return nil
	}
	if err := stopUnitGroup(units...); err != nil {
		return err
	}
	var errs []error
	for _, unit := range units {
		if err := disableService(unit); err != nil && !missingUnitError(err) {
			errs = append(errs, err)
		}
		if err := maskService(unit); err != nil && !missingUnitError(err) {
			errs = append(errs, err)
		}
	}
	for _, unit := range units {
		inactive, err := unitInactive(unit)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !inactive {
			errs = append(errs, fmt.Errorf("hostpackages: %s still active after quiesce", unit))
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
	// Full first-time host-package closures can take several minutes (and used to
	// hit a global 30s exec kill with "signal: killed").
	if _, err := runCommandWithTimeout(15*time.Minute, "dpkg", args...); err != nil {
		return fmt.Errorf("hostpackages: install packages: %w", err)
	}
	return nil
}

func removePackages(names []string) error {
	if len(names) == 0 {
		return nil
	}
	args := append([]string{"--remove"}, names...)
	if _, err := runCommandWithTimeout(5*time.Minute, "dpkg", args...); err != nil {
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
	if strings.Contains(text, "disabled") || strings.Contains(text, "static") || strings.Contains(text, "indirect") || strings.Contains(text, "masked") || strings.Contains(text, "not-found") || strings.Contains(text, "No such file") {
		return false, nil
	}
	return false, fmt.Errorf("hostpackages: systemctl is-enabled %s: %w", name, err)
}

func isServiceActive(name string) (bool, error) {
	out, err := runCommand("systemctl", "is-active", name)
	state := strings.TrimSpace(out)
	if state == "active" {
		return true, nil
	}
	// Non-zero exit for inactive/failed/unknown is normal.
	if state == "activating" || state == "reloading" {
		return false, nil
	}
	if err == nil {
		return false, nil
	}
	text := err.Error()
	if strings.Contains(text, "inactive") || strings.Contains(text, "failed") || strings.Contains(text, "unknown") || strings.Contains(text, "not found") || missingUnitError(err) {
		return false, nil
	}
	if state != "" && state != "active" {
		return false, nil
	}
	return false, fmt.Errorf("hostpackages: systemctl is-active %s: %w", name, err)
}

// isUnitInactive reports whether a unit is an acceptable quiesced state
// (inactive, failed, dead, missing, masked-and-idle). activating/active are not.
func isUnitInactive(name string) (bool, error) {
	out, err := runCommand("systemctl", "is-active", name)
	state := strings.TrimSpace(out)
	switch state {
	case "active", "activating", "reloading":
		return false, nil
	case "inactive", "failed", "deactivating", "dead", "unknown":
		return true, nil
	}
	if err != nil {
		text := strings.ToLower(err.Error())
		if missingUnitError(err) || strings.Contains(text, "inactive") || strings.Contains(text, "failed") || strings.Contains(text, "not found") {
			return true, nil
		}
		if state == "" {
			return true, nil
		}
		return false, fmt.Errorf("hostpackages: systemctl is-active %s: %w", name, err)
	}
	// Any other non-active reported state counts as quiesced.
	return state != "active", nil
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
	return systemctlStopUnitGroup(name)
}

// systemctlStopUnitGroup stops one or more units in a single job so socket
// activation cannot cancel a peer stop. Retries on canceled jobs; succeeds when
// every unit is inactive regardless of the stop command's exit status.
func systemctlStopUnitGroup(units ...string) error {
	filtered := make([]string, 0, len(units))
	for _, unit := range units {
		unit = strings.TrimSpace(unit)
		if unit != "" {
			filtered = append(filtered, unit)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	const attempts = 6
	var last error
	for i := 0; i < attempts; i++ {
		if allInactive, _ := allUnitsInactive(filtered); allInactive {
			return nil
		}
		args := append([]string{"stop", "--job-mode=replace"}, filtered...)
		_, err := runCommand("systemctl", args...)
		if err == nil || missingUnitError(err) {
			if allInactive, _ := allUnitsInactive(filtered); allInactive {
				return nil
			}
		} else {
			last = err
			// Canceled / replace races: still check outcome before failing.
			if allInactive, _ := allUnitsInactive(filtered); allInactive {
				return nil
			}
			if !jobCanceledError(err) && !jobReplaceError(err) {
				// Last resort: kill remaining active members, then re-check.
				_, _ = runCommand("systemctl", append([]string{"kill", "--kill-who=all", "-s", "SIGTERM"}, filtered...)...)
				time.Sleep(200 * time.Millisecond)
				if allInactive, _ := allUnitsInactive(filtered); allInactive {
					return nil
				}
				return fmt.Errorf("hostpackages: stop %s: %w", strings.Join(filtered, " "), err)
			}
		}
		time.Sleep(time.Duration(100*(i+1)) * time.Millisecond)
	}
	if allInactive, _ := allUnitsInactive(filtered); allInactive {
		return nil
	}
	if last == nil {
		last = fmt.Errorf("units still active")
	}
	return fmt.Errorf("hostpackages: stop %s: %w", strings.Join(filtered, " "), last)
}

func allUnitsInactive(units []string) (bool, error) {
	for _, unit := range units {
		inactive, err := unitInactive(unit)
		if err != nil {
			return false, err
		}
		if !inactive {
			return false, nil
		}
	}
	return true, nil
}

func systemctlUnmask(name string) error {
	_, err := runCommand("systemctl", "unmask", name)
	if err != nil && !missingUnitError(err) {
		return fmt.Errorf("hostpackages: unmask %s: %w", name, err)
	}
	return nil
}

func systemctlMask(name string) error {
	_, err := runCommand("systemctl", "mask", "--now", name)
	if err != nil && !missingUnitError(err) {
		// --now may fail on already-stopped units with canceled jobs; fall back.
		if jobCanceledError(err) {
			_, err = runCommand("systemctl", "mask", name)
			if err == nil || missingUnitError(err) {
				return nil
			}
		}
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

func jobCanceledError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "canceled") || strings.Contains(text, "cancelled")
}

func jobReplaceError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "job for") && strings.Contains(text, "failed")
}

var runCommand = func(name string, args ...string) (string, error) {
	return runCommandWithTimeout(30*time.Second, name, args...)
}

func runCommandWithTimeout(timeout time.Duration, name string, args ...string) (string, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	// Avoid interactive debconf on constrained CI / package reinstalls.
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("%s %s: timed out after %s: %s", name, strings.Join(args, " "), timeout, strings.TrimSpace(string(out)))
		}
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
