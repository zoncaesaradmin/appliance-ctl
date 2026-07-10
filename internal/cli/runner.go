// Package cli provides a small, injectable wrapper around invoking
// bundled external binaries (ctr, helm, kubectl). Adapters depend on the
// Runner function type rather than exec.Command directly, so they can be
// unit tested with a fake runner instead of requiring the real binaries
// and a live cluster.
package cli

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Runner invokes name with args and returns its combined output. It is
// the seam every CLI-shelling adapter in this repo is built against.
type Runner func(ctx context.Context, name string, args ...string) (string, error)

// InputRunner is the stdin-aware variant used when a command must read
// protected input such as a first-admin bootstrap password.
type InputRunner func(ctx context.Context, stdin []byte, name string, args ...string) (string, error)

// Exec is the default, real Runner: it runs the named binary via
// exec.CommandContext and returns its combined stdout/stderr.
func Exec(ctx context.Context, name string, args ...string) (string, error) {
	return ExecInput(ctx, nil, name, args...)
}

// ExecInput is the stdin-aware counterpart to Exec. The provided stdin
// bytes never appear in the logged command line or returned error text.
func ExecInput(ctx context.Context, stdin []byte, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("cli: %s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
