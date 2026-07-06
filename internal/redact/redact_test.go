package redact_test

import (
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/redact"
)

func TestRedactor_ScrubsRegisteredSecret(t *testing.T) {
	r := redact.New()
	r.Register("s3cr3t-password")

	got := r.Redact("connecting with password s3cr3t-password to the database")
	if strings.Contains(got, "s3cr3t-password") {
		t.Errorf("expected secret to be scrubbed, got %q", got)
	}
	if !strings.Contains(got, redact.Placeholder) {
		t.Errorf("expected placeholder in output, got %q", got)
	}
}

func TestRedactor_IgnoresEmptyString(t *testing.T) {
	r := redact.New()
	r.Register("")

	got := r.Redact("nothing secret here")
	if got != "nothing secret here" {
		t.Errorf("expected unset secret to leave text untouched, got %q", got)
	}
}

// A secret that is a substring of another registered secret must not
// leave a fragment of the longer secret exposed.
func TestRedactor_LongestFirstAvoidsPartialLeak(t *testing.T) {
	r := redact.New()
	r.Register("abc")       // registered short-first
	r.Register("abcdefghi") // registered second, but longer

	got := r.Redact("token=abcdefghi")
	if strings.Contains(got, "defghi") {
		t.Errorf("expected the full longer secret to be redacted first, got %q", got)
	}
}

func TestRedactor_DoesNotRegisterDuplicates(t *testing.T) {
	r := redact.New()
	r.Register("dup")
	r.Register("dup")

	got := r.Redact("dup dup")
	want := redact.Placeholder + " " + redact.Placeholder
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
