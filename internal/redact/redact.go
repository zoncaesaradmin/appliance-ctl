// Package redact scrubs secret values from log output and support
// bundles. Secrets are generated on the target and registered here as
// soon as they exist; every subsequent log line has those exact values
// replaced before being written. See "Secrets are generated on the
// target... They never appear in ... logs" in docs/release-plan.md.
package redact

import (
	"sort"
	"strings"
	"sync"
)

const Placeholder = "***REDACTED***"

// Redactor holds the set of secret values known so far and scrubs them
// from arbitrary strings.
type Redactor struct {
	mu      sync.RWMutex
	secrets []string
}

// New returns an empty Redactor.
func New() *Redactor {
	return &Redactor{}
}

// Register adds a secret value to scrub from all future Redact calls.
// Empty strings are ignored so an unset/blank field never turns into a
// blanket redaction of ordinary text.
func (r *Redactor) Register(secret string) {
	if secret == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, s := range r.secrets {
		if s == secret {
			return
		}
	}
	r.secrets = append(r.secrets, secret)

	// Longest-first so a secret that is a substring of another registered
	// secret does not get partially replaced first and hide the rest.
	sort.Slice(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
}

// Redact replaces every occurrence of every registered secret in s with
// Placeholder.
func (r *Redactor) Redact(s string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, secret := range r.secrets {
		s = strings.ReplaceAll(s, secret, Placeholder)
	}
	return s
}
