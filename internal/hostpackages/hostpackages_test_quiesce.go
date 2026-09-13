package hostpackages

import (
	"errors"
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
	// avahi-daemon + dnsmasq + hostapd × stop/disable/mask
	if len(actions) != 9 {
		t.Fatalf("actions = %v (len=%d), want stop/disable/mask for three units", actions, len(actions))
	}
	found := map[string]bool{}
	for _, a := range actions {
		found[a] = true
	}
	for _, unit := range []string{"avahi-daemon.service", "dnsmasq.service", "hostapd.service"} {
		for _, op := range []string{"stop", "disable", "mask"} {
			key := op + ":" + unit
			if !found[key] {
				t.Fatalf("missing action %s in %v", key, actions)
			}
		}
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
	unmaskService = func(string) error { actions = append(actions, "unmask"); return nil }
	enableService = func(string) error { actions = append(actions, "enable"); return nil }
	restartService = func(string) error { actions = append(actions, "restart"); return nil }
	debPackageName = func(string) (string, error) { return "avahi-daemon", nil }

	if _, err := InstallRequiredPackages(InstallSpec{
		RootDir: root, OS: "ubuntu", OSVersion: "24.04", Arch: "amd64", ServiceName: MDNSServiceName,
	}); err != nil {
		t.Fatalf("InstallRequiredPackages: %v", err)
	}

	wantSuffix := []string{"install", "stop", "disable", "mask", "stop", "disable", "mask", "stop", "disable", "mask", "unmask", "enable", "restart"}
	if len(actions) != len(wantSuffix) {
		t.Fatalf("actions = %v, want %v", actions, wantSuffix)
	}
	for i, want := range wantSuffix {
		if actions[i] != want {
			t.Fatalf("actions[%d] = %q, want %q; all actions: %v", i, actions[i], want, actions)
		}
	}
}
