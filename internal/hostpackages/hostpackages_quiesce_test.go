package hostpackages

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQuiesceConflictingHostDaemonsIgnoresMissing(t *testing.T) {
	origStopGroup, origDisable, origMask := stopUnitGroup, disableService, maskService
	origInactive := unitInactive
	t.Cleanup(func() {
		stopUnitGroup, disableService, maskService = origStopGroup, origDisable, origMask
		unitInactive = origInactive
	})
	var stopped []string
	var actions []string
	stopUnitGroup = func(units ...string) error {
		stopped = append([]string{}, units...)
		return nil
	}
	disableService = func(name string) error {
		actions = append(actions, "disable:"+name)
		return errors.New("systemctl disable hostapd.service: No such file")
	}
	maskService = func(name string) error {
		actions = append(actions, "mask:"+name)
		return errors.New("systemctl mask dnsmasq.service: not found")
	}
	unitInactive = func(string) (bool, error) { return true, nil }

	if err := QuiesceConflictingHostDaemons(); err != nil {
		t.Fatalf("expected missing units to be ignored, got: %v", err)
	}
	if strings.Join(stopped, ",") != "dnsmasq.service,hostapd.service" {
		t.Fatalf("stopped group = %v, want dnsmasq+hostapd only (no avahi)", stopped)
	}
	for _, unit := range []string{"dnsmasq.service", "hostapd.service"} {
		if !containsAction(actions, "disable:"+unit) || !containsAction(actions, "mask:"+unit) {
			t.Fatalf("missing disable/mask for %s in %v", unit, actions)
		}
	}
	for _, a := range actions {
		if strings.Contains(a, "avahi") {
			t.Fatalf("conflict quiesce must not touch avahi: %v", actions)
		}
	}
}

func TestQuiesceMDNSUnitsStopsSocketAndServiceTogether(t *testing.T) {
	origStopGroup, origDisable, origMask := stopUnitGroup, disableService, maskService
	origInactive := unitInactive
	t.Cleanup(func() {
		stopUnitGroup, disableService, maskService = origStopGroup, origDisable, origMask
		unitInactive = origInactive
	})
	var stopped []string
	stopUnitGroup = func(units ...string) error {
		stopped = append([]string{}, units...)
		return nil
	}
	disableService = func(string) error { return nil }
	maskService = func(string) error { return nil }
	unitInactive = func(string) (bool, error) { return true, nil }

	if err := QuiesceMDNSUnits(); err != nil {
		t.Fatalf("QuiesceMDNSUnits: %v", err)
	}
	if len(stopped) != 2 || stopped[0] != mdnsSocketName || stopped[1] != mdnsServiceName {
		t.Fatalf("mdns stop group = %v, want socket then service", stopped)
	}
}

func TestInstallRequiredPackagesLANDiscoveryLeavesAvahiRunning(t *testing.T) {
	origInstalled, origInstall, origRemove := installedPackageSet, installDebArchives, removeNamedPackages
	origEnabled, origActive := serviceEnabled, serviceActive
	origEnable, origUnmask := enableService, unmaskService
	origStop, origDisable, origMask := stopService, disableService, maskService
	origStopGroup, origInactive := stopUnitGroup, unitInactive
	origStart := startService
	origDebName := debPackageName
	t.Cleanup(func() {
		installedPackageSet, installDebArchives, removeNamedPackages = origInstalled, origInstall, origRemove
		serviceEnabled, serviceActive = origEnabled, origActive
		enableService, unmaskService = origEnable, origUnmask
		stopService, disableService, maskService = origStop, origDisable, origMask
		stopUnitGroup, unitInactive = origStopGroup, origInactive
		startService = origStart
		debPackageName = origDebName
	})

	root := t.TempDir()
	packageDir := filepath.Join(root, "ubuntu", "24.04", "amd64")
	if err := os.MkdirAll(packageDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "avahi.deb"), nil, 0o640); err != nil {
		t.Fatal(err)
	}

	var actions []string
	installedPackageSet = func() (map[string]struct{}, error) { return map[string]struct{}{}, nil }
	installDebArchives = func([]string) error { actions = append(actions, "install"); return nil }
	removeNamedPackages = func([]string) error { return nil }
	serviceEnabled = func(string) (bool, error) { return false, nil }
	avahiActive := false
	serviceActive = func(name string) (bool, error) {
		if name == mdnsServiceName {
			return avahiActive, nil
		}
		return false, nil
	}
	stopUnitGroup = func(units ...string) error {
		actions = append(actions, "stop-group:"+strings.Join(units, ","))
		return nil
	}
	disableService = func(name string) error { actions = append(actions, "disable:"+name); return nil }
	maskService = func(name string) error { actions = append(actions, "mask:"+name); return nil }
	unmaskService = func(name string) error { actions = append(actions, "unmask:"+name); return nil }
	enableService = func(name string) error { actions = append(actions, "enable:"+name); return nil }
	startService = func(name string) error {
		actions = append(actions, "start:"+name)
		avahiActive = true
		return nil
	}
	unitInactive = func(string) (bool, error) { return true, nil }
	debPackageName = func(string) (string, error) { return "avahi-daemon", nil }

	if _, err := InstallRequiredPackages(InstallSpec{
		RootDir: root, OS: "ubuntu", OSVersion: "24.04", Arch: "amd64", ServiceName: MDNSServiceName,
	}); err != nil {
		t.Fatalf("InstallRequiredPackages: %v", err)
	}

	// Conflict daemons quiesced; avahi never stopped/masked; avahi unmasked+started.
	want := []string{
		"install",
		"stop-group:dnsmasq.service,hostapd.service",
		"disable:dnsmasq.service", "mask:dnsmasq.service",
		"disable:hostapd.service", "mask:hostapd.service",
		"unmask:avahi-daemon.socket",
		"unmask:avahi-daemon.service",
		"enable:avahi-daemon.service",
		"start:avahi-daemon.service",
	}
	if strings.Join(actions, "|") != strings.Join(want, "|") {
		t.Fatalf("actions =\n%v\nwant\n%v", actions, want)
	}
}

func TestInstallRequiredPackagesWithoutLANDiscoveryQuiescesAvahi(t *testing.T) {
	origInstalled, origInstall, origRemove := installedPackageSet, installDebArchives, removeNamedPackages
	origStopGroup, origDisable, origMask := stopUnitGroup, disableService, maskService
	origInactive := unitInactive
	origDebName := debPackageName
	t.Cleanup(func() {
		installedPackageSet, installDebArchives, removeNamedPackages = origInstalled, origInstall, origRemove
		stopUnitGroup, disableService, maskService = origStopGroup, origDisable, origMask
		unitInactive = origInactive
		debPackageName = origDebName
	})

	root := t.TempDir()
	packageDir := filepath.Join(root, "ubuntu", "24.04", "amd64")
	if err := os.MkdirAll(packageDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "avahi.deb"), nil, 0o640); err != nil {
		t.Fatal(err)
	}

	var stopGroups []string
	installedPackageSet = func() (map[string]struct{}, error) { return map[string]struct{}{"avahi-daemon": {}}, nil }
	installDebArchives = func([]string) error { return nil }
	removeNamedPackages = func([]string) error { return nil }
	stopUnitGroup = func(units ...string) error {
		stopGroups = append(stopGroups, strings.Join(units, ","))
		return nil
	}
	disableService = func(string) error { return nil }
	maskService = func(string) error { return nil }
	unitInactive = func(string) (bool, error) { return true, nil }
	debPackageName = func(string) (string, error) { return "avahi-daemon", nil }

	if _, err := InstallRequiredPackages(InstallSpec{
		RootDir: root, OS: "ubuntu", OSVersion: "24.04", Arch: "amd64", ServiceName: "",
	}); err != nil {
		t.Fatalf("InstallRequiredPackages: %v", err)
	}
	if len(stopGroups) != 2 {
		t.Fatalf("stop groups = %v, want conflict then mdns", stopGroups)
	}
	if stopGroups[0] != "dnsmasq.service,hostapd.service" {
		t.Fatalf("first stop group = %q", stopGroups[0])
	}
	if stopGroups[1] != "avahi-daemon.socket,avahi-daemon.service" {
		t.Fatalf("second stop group = %q", stopGroups[1])
	}
}

func TestEnsureFeatureUnitsRunningSkipsRestartWhenAlreadyActive(t *testing.T) {
	origActive, origUnmask, origEnable, origStart := serviceActive, unmaskService, enableService, startService
	t.Cleanup(func() {
		serviceActive, unmaskService, enableService, startService = origActive, origUnmask, origEnable, origStart
	})
	var actions []string
	serviceActive = func(string) (bool, error) { return true, nil }
	unmaskService = func(name string) error { actions = append(actions, "unmask:"+name); return nil }
	enableService = func(string) error { actions = append(actions, "enable"); return nil }
	startService = func(string) error { actions = append(actions, "start"); return nil }

	if err := EnsureFeatureUnitsRunning(MDNSServiceName); err != nil {
		t.Fatalf("EnsureFeatureUnitsRunning: %v", err)
	}
	want := []string{"unmask:avahi-daemon.socket", "unmask:avahi-daemon.service"}
	if strings.Join(actions, "|") != strings.Join(want, "|") {
		t.Fatalf("actions = %v, want unmask only (no restart of live avahi)", actions)
	}
}

func TestSystemctlStopUnitGroupSucceedsWhenCanceledButInactive(t *testing.T) {
	origRun := runCommand
	origInactive := unitInactive
	t.Cleanup(func() {
		runCommand = origRun
		unitInactive = origInactive
	})
	attempts := 0
	runCommand = func(name string, args ...string) (string, error) {
		if name != "systemctl" || len(args) < 1 || args[0] != "stop" {
			t.Fatalf("unexpected %s %v", name, args)
		}
		attempts++
		return "", fmt.Errorf("systemctl stop: exit status 1: Job for avahi-daemon.socket canceled.")
	}
	unitInactive = func(string) (bool, error) { return true, nil }

	if err := systemctlStopUnitGroup(mdnsSocketName, mdnsServiceName); err != nil {
		t.Fatalf("expected canceled+inactive to succeed, got: %v", err)
	}
	if attempts != 0 {
		t.Fatalf("attempts = %d, want 0 (already inactive short-circuit before stop)", attempts)
	}
}

func TestSystemctlStopUnitGroupRetriesCanceledUntilInactive(t *testing.T) {
	origRun := runCommand
	origInactive := unitInactive
	t.Cleanup(func() {
		runCommand = origRun
		unitInactive = origInactive
	})
	checks := 0
	unitInactive = func(string) (bool, error) {
		checks++
		// First allUnitsInactive probe (2 units) + after first stop (2) → still active;
		// after second stop → inactive. Count per-unit calls.
		return checks > 4, nil
	}
	stops := 0
	runCommand = func(name string, args ...string) (string, error) {
		if name != "systemctl" || len(args) < 1 || args[0] != "stop" {
			t.Fatalf("unexpected %s %v", name, args)
		}
		stops++
		return "", fmt.Errorf("systemctl stop: exit status 1: Job for avahi-daemon.socket canceled.")
	}
	if err := systemctlStopUnitGroup(mdnsSocketName, mdnsServiceName); err != nil {
		t.Fatalf("expected eventual inactive success, got: %v", err)
	}
	if stops < 1 {
		t.Fatalf("expected at least one stop attempt, got %d", stops)
	}
}

func containsAction(actions []string, want string) bool {
	for _, a := range actions {
		if a == want {
			return true
		}
	}
	return false
}
