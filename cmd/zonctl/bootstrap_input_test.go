package main

import (
	"strings"
	"testing"
)

func TestValidateBootstrapPasswordLength(t *testing.T) {
	cases := []struct {
		name    string
		length  int
		wantErr bool
	}{
		{"too short (13 chars)", 13, true},
		{"exactly minimum (14 chars)", 14, false},
		{"comfortably in range", 20, false},
		{"exactly maximum (128 chars)", 128, false},
		{"too long (129 chars)", 129, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			password := []byte(strings.Repeat("a", tc.length))
			err := validateBootstrapPasswordLength(password)
			if tc.wantErr && err == nil {
				t.Errorf("expected an error for a %d-character password, got nil", tc.length)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error for a %d-character password, got: %v", tc.length, err)
			}
		})
	}
}

// readBootstrapPassword is the --bootstrap-password-stdin path; it must
// reject a too-short password immediately, before any install work runs,
// rather than only failing much later when the server rejects it after
// K3s and the chart are already fully installed.
func TestReadBootstrapPassword_RejectsShortPasswordUpfront(t *testing.T) {
	_, err := readBootstrapPassword(strings.NewReader("short-pass\n"))
	if err == nil {
		t.Fatal("expected a short password to be rejected")
	}
	if !strings.Contains(err.Error(), "at least 14 characters") {
		t.Errorf("expected a clear minimum-length error, got: %v", err)
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
