package hostpackages

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestQuiesceStockDaemonUnitsIgnoresMissing(t *testing.T) {
	origStop, origDisable, origMask := stopService, disableService, maskService
	t.Cleanup(func() {
		stopService, disableService, maskService = origStop, origDisable, origMask
	})
	var actions []string
	stopService = func(name string) error {
		actions = append(actions, "stop:"+name)
		return errors.New("systemctl is-active dnsmasq.service: exit status 4: Unit dnsmasq.service could not be found")
	}
	disableService = func(name string) error {
		actions = append(actions, "disable:"+name)
		return errors.New("systemctl disable hostapd.service: No such file")
	}
	maskService = func(name string) error {
		actions = append(actions, "mask:"+name)
		return errors.New("systemctl mask dnsmasq.service: not found")
	}
	if err := QuiesceStockDaemonUnits(); err != nil {
		t.Fatalf("expected missing units to be ignored, got: %v", err)
	}
	// avahi-daemon.socket + avahi-daemon.service + dnsmasq + hostapd × stop/disable/mask
	if len(actions) != 12 {
		t.Fatalf("actions = %v (len=%d), want stop/disable/mask for four units", actions, len(actions))
	}
	found := map[string]bool{}
	for _, a := range actions {
		found[a] = true
	}
	for _, unit := range []string{"avahi-daemon.socket", "avahi-daemon.service", "dnsmasq.service", "hostapd.service"} {
		for _, op := range []string{"stop", "disable", "mask"} {
			key := op + ":" + unit
			if !found[key] {
				t.Fatalf("missing action %s in %v", key, actions)
			}
		}
	}
	// Socket must be quiesced before the service so activation cannot cancel stop.
	socketStop, serviceStop := -1, -1
	for i, a := range actions {
		switch a {
		case "stop:avahi-daemon.socket":
			socketStop = i
		case "stop:avahi-daemon.service":
			serviceStop = i
		}
	}
	if socketStop < 0 || serviceStop < 0 || socketStop > serviceStop {
		t.Fatalf("avahi socket stop must precede service stop; actions=%v", actions)
	}
}

func TestInstallRequiredPackagesUnmasksSelectedServiceBeforeEnable(t *testing.T) {
	origInstalled, origInstall, origRemove := installedPackageSet, installDebArchives, removeNamedPackages
	origEnabled, origActive := serviceEnabled, serviceActive
	origEnable, origRestart, origUnmask := enableService, restartService, unmaskService
	origStop, origDisable, origMask := stopService, disableService, maskService
	origDebName := debPackageName
	t.Cleanup(func() {
		installedPackageSet, installDebArchives, removeNamedPackages = origInstalled, origInstall, origRemove
		serviceEnabled, serviceActive = origEnabled, origActive
		enableService, restartService, unmaskService = origEnable, origRestart, origUnmask
		stopService, disableService, maskService = origStop, origDisable, origMask
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
	installDebArchives = func(paths []string) error { actions = append(actions, "install"); return nil }
	removeNamedPackages = func([]string) error { return nil }
	serviceEnabled = func(string) (bool, error) { return false, nil }
	serviceActive = func(string) (bool, error) { return false, nil }
	stopService = func(string) error { actions = append(actions, "stop"); return nil }
	disableService = func(string) error { actions = append(actions, "disable"); return nil }
	maskService = func(string) error { actions = append(actions, "mask"); return nil }
	unmaskService = func(name string) error { actions = append(actions, "unmask:"+name); return nil }
	enableService = func(string) error { actions = append(actions, "enable"); return nil }
	restartService = func(string) error { actions = append(actions, "restart"); return nil }
	debPackageName = func(string) (string, error) { return "avahi-daemon", nil }

	if _, err := InstallRequiredPackages(InstallSpec{
		RootDir: root, OS: "ubuntu", OSVersion: "24.04", Arch: "amd64", ServiceName: MDNSServiceName,
	}); err != nil {
		t.Fatalf("InstallRequiredPackages: %v", err)
	}

	wantSuffix := []string{
		"install",
		"stop", "disable", "mask", // avahi-daemon.socket
		"stop", "disable", "mask", // avahi-daemon.service
		"stop", "disable", "mask", // dnsmasq.service
		"stop", "disable", "mask", // hostapd.service
		"unmask:avahi-daemon.socket",
		"unmask:avahi-daemon.service",
		"enable", "restart",
	}
	if len(actions) != len(wantSuffix) {
		t.Fatalf("actions = %v, want %v", actions, wantSuffix)
	}
	for i, want := range wantSuffix {
		if actions[i] != want {
			t.Fatalf("actions[%d] = %q, want %q; all actions: %v", i, actions[i], want, actions)
		}
	}
}

func TestSystemctlStopRetriesCanceledJobs(t *testing.T) {
	origRun := runCommand
	t.Cleanup(func() { runCommand = origRun })

	attempts := 0
	runCommand = func(name string, args ...string) (string, error) {
		if name != "systemctl" || len(args) < 2 || args[0] != "stop" {
			t.Fatalf("unexpected command %s %v", name, args)
		}
		attempts++
		if attempts < 3 {
			return "", fmt.Errorf("systemctl stop %s: exit status 1: Job for %s canceled.", args[1], args[1])
		}
		return "", nil
	}
	if err := systemctlStop("avahi-daemon.service"); err != nil {
		t.Fatalf("systemctlStop: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}
