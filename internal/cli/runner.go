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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Runner invokes name with args and returns stdout on success. It is the
// seam every CLI-shelling adapter in this repo is built against.
type Runner func(ctx context.Context, name string, args ...string) (string, error)

// InputRunner is the stdin-aware variant used when a command must read
// protected input such as a credential file on stdin.
type InputRunner func(ctx context.Context, stdin []byte, name string, args ...string) (string, error)

// Exec is the default, real Runner: it runs the named binary via
// exec.CommandContext. On success it returns stdout only so kubectl/helm
// warnings on stderr cannot corrupt machine-parsed payloads (Secret data,
// jsonpath values, digests). On failure, stderr is included in the error.
func Exec(ctx context.Context, name string, args ...string) (string, error) {
	return ExecInput(ctx, nil, name, args...)
}

// ExecToFile streams stdout directly to an atomically published protected
// file. It is for large, binary artifacts such as pg_dump output; callers
// must not route such data through Runner's in-memory string result.
func ExecToFile(ctx context.Context, destination, name string, args ...string) error {
	dir := filepath.Dir(destination)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".stream-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = tmp
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cli: %s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, destination)
}

// ExecInput is the stdin-aware counterpart to Exec. The provided stdin
// bytes never appear in the logged command line or returned error text.
func ExecInput(ctx context.Context, stdin []byte, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := stdout.String()
	if err != nil {
		detail := strings.TrimSpace(out + "\n" + stderr.String())
		return out, fmt.Errorf("cli: %s %s: %w: %s", name, strings.Join(args, " "), err, detail)
	}
	return out, nil
}
