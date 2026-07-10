package main

import (
	"strings"
	"testing"
)

// Password policy (length, composition) is enforced server-side only
// (appliance-code's internal/authn.ValidatePasswordPolicy). The client
// must not duplicate or pre-empt that policy: a rejected password fails
// the bootstrap step non-fatally (install.ErrBootstrapFailed), after the
// K3s + chart install has already fully completed — it must never block
// the install itself from starting.
func TestReadBootstrapPassword_DoesNotRejectShortPasswords(t *testing.T) {
	got, err := readBootstrapPassword(strings.NewReader("short\n"))
	if err != nil {
		t.Fatalf("expected no client-side length rejection, got: %v", err)
	}
	if string(got) != "short" {
		t.Errorf("expected trailing newline to be trimmed, got %q", got)
	}
}

func TestReadBootstrapPassword_RejectsEmptyPassword(t *testing.T) {
	_, err := readBootstrapPassword(strings.NewReader("\n"))
	if err == nil {
		t.Fatal("expected an empty password to still be rejected")
	}
}

func TestReadBootstrapPassword_AcceptsValidPassword(t *testing.T) {
	got, err := readBootstrapPassword(strings.NewReader("a-fully-valid-password\n"))
	if err != nil {
		t.Fatalf("expected a valid password to be accepted, got: %v", err)
	}
	if string(got) != "a-fully-valid-password" {
		t.Errorf("expected trailing newline to be trimmed, got %q", got)
	}
}
