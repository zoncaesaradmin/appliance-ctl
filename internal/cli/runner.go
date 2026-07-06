// Package cli provides a small, injectable wrapper around invoking
// bundled external binaries (ctr, helm, kubectl). Adapters depend on the
// Runner function type rather than exec.Command directly, so they can be
// unit tested with a fake runner instead of requiring the real binaries
// and a live cluster.
package cli

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Runner invokes name with args and returns its combined output. It is
// the seam every CLI-shelling adapter in this repo is built against.
type Runner func(ctx context.Context, name string, args ...string) (string, error)

// Exec is the default, real Runner: it runs the named binary via
// exec.CommandContext and returns its combined stdout/stderr.
func Exec(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("cli: %s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
