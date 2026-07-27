package hostdns

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDropInContentsDisablesStub(t *testing.T) {
	if !strings.Contains(dropInContents, "DNSStubListener=no") || !strings.Contains(dropInContents, "[Resolve]") {
		t.Fatalf("drop-in missing required stanza:\n%s", dropInContents)
	}
}

func TestSysctlDropInAllowsPrivilegedBind(t *testing.T) {
	if !strings.Contains(sysctlDropInContents, "net.ipv4.ip_unprivileged_port_start=0") {
		t.Fatalf("sysctl drop-in missing unprivileged port floor:\n%s", sysctlDropInContents)
	}
}

func TestEnsureUnprivilegedPortStart_WritesAndApplies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "99-zon-appliance-dns.conf")
	prevPath := SysctlPath
	SysctlPath = path
	t.Cleanup(func() { SysctlPath = prevPath })

	var applied []string
	prevApply, prevRead := applySysctl, readSysctl
	applySysctl = func(key, value string) error {
		applied = append(applied, key+"="+value)
		return nil
	}
	readSysctl = func(string) (string, error) { return "1024", nil }
	t.Cleanup(func() {
		applySysctl = prevApply
		readSysctl = prevRead
	})

	var result PrepareResult
	if err := ensureUnprivilegedPortStart(&result); err != nil {
		t.Fatal(err)
	}
	if !result.WroteSysctlDropIn || !result.Changed {
		t.Fatalf("result = %+v, want WroteSysctlDropIn and Changed", result)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != sysctlDropInContents {
		t.Fatalf("drop-in content mismatch:\n%s", data)
	}
	if len(applied) != 1 || applied[0] != "net.ipv4.ip_unprivileged_port_start=0" {
		t.Fatalf("applied=%v", applied)
	}

	// Idempotent when already at 0 and file matches.
	applied = nil
	result = PrepareResult{}
	readSysctl = func(string) (string, error) { return "0", nil }
	if err := ensureUnprivilegedPortStart(&result); err != nil {
		t.Fatal(err)
	}
	if result.WroteSysctlDropIn || result.Changed {
		t.Fatalf("idempotent result = %+v", result)
	}
	if len(applied) != 0 {
		t.Fatalf("unexpected sysctl writes: %v", applied)
	}
}

func TestWaitUntilWildcard53Free_PollsUntilBindSucceeds(t *testing.T) {
	origListen := listenTCP53
	origSleep := sleep
	t.Cleanup(func() {
		listenTCP53 = origListen
		sleep = origSleep
	})

	attempts := 0
	listenTCP53 = func() (net.Listener, error) {
		attempts++
		if attempts < 3 {
			return nil, errors.New("bind: address already in use")
		}
		return &stubListener{}, nil
	}
	var slept time.Duration
	sleep = func(d time.Duration) { slept += d }

	if !waitUntilWildcard53Free(time.Second, 50*time.Millisecond) {
		t.Fatal("expected waitUntilWildcard53Free to succeed after transient conflicts")
	}
	if attempts != 3 {
		t.Fatalf("listen attempts=%d, want 3", attempts)
	}
	if slept < 50*time.Millisecond {
		t.Fatalf("expected at least one poll sleep, got %s", slept)
	}
}

func TestWaitUntilWildcard53Free_TimesOut(t *testing.T) {
	origListen := listenTCP53
	origSleep := sleep
	t.Cleanup(func() {
		listenTCP53 = origListen
		sleep = origSleep
	})

	listenTCP53 = func() (net.Listener, error) {
		return nil, errors.New("bind: address already in use")
	}
	sleep = func(time.Duration) {}

	if waitUntilWildcard53Free(30*time.Millisecond, 10*time.Millisecond) {
		t.Fatal("expected timeout while port stays busy")
	}
}

type stubListener struct{}

func (stubListener) Accept() (net.Conn, error) { return nil, errors.New("unused") }
func (stubListener) Close() error              { return nil }
func (stubListener) Addr() net.Addr            { return &net.TCPAddr{Port: 53} }

func TestEnsureUpstreamResolvConf_RelinksStubToUplink(t *testing.T) {
	tmp := t.TempDir()
	upstream := filepath.Join(tmp, "upstream-resolv.conf")
	resolv := filepath.Join(tmp, "resolv.conf")
	stub := filepath.Join(tmp, "stub-resolv.conf")
	if err := os.WriteFile(upstream, []byte("nameserver 1.1.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stub, []byte("nameserver 127.0.0.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(stub, resolv); err != nil {
		t.Fatal(err)
	}

	_ = os.Remove(resolv)
	if err := os.Symlink(upstream, resolv); err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(resolv)
	if err != nil || target != upstream {
		t.Fatalf("resolv.conf target = %q err=%v, want %q", target, err, upstream)
	}
}
