package hostdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDropInContentsDisablesStub(t *testing.T) {
	if !strings.Contains(dropInContents, "DNSStubListener=no") || !strings.Contains(dropInContents, "[Resolve]") {
		t.Fatalf("drop-in missing required stanza:\n%s", dropInContents)
	}
}

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
