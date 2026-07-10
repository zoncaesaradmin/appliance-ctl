package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

const defaultBootstrapAdminUsername = "admin"

// Mirrors appliance-code's internal/authn.ValidatePasswordPolicy (ADR
// 0010) so a too-short/too-long password is rejected here, before the
// (multi-minute) K3s + chart install runs, instead of only surfacing
// after all of that succeeds, at the very last step. Keep in sync with
// that policy if it ever changes.
const (
	minBootstrapPasswordLength = 14
	maxBootstrapPasswordLength = 128
)

func validateBootstrapPasswordLength(password []byte) error {
	length := len([]rune(string(password)))
	if length < minBootstrapPasswordLength {
		return fmt.Errorf("install: bootstrap password must be at least %d characters", minBootstrapPasswordLength)
	}
	if length > maxBootstrapPasswordLength {
		return fmt.Errorf("install: bootstrap password must be at most %d characters", maxBootstrapPasswordLength)
	}
	return nil
}

type bootstrapCredentials struct {
	username string
	password []byte
}

func resolveBootstrapCredentials(opts cliOptions) (bootstrapCredentials, error) {
	username := strings.TrimSpace(opts.bootstrapAdminUser)
	if username == "" {
		username = defaultBootstrapAdminUsername
	}

	if opts.bootstrapPassStdin {
		password, err := readBootstrapPassword(os.Stdin)
		if err != nil {
			return bootstrapCredentials{}, err
		}
		return bootstrapCredentials{username: username, password: password}, nil
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return bootstrapCredentials{}, fmt.Errorf("install: first-admin bootstrap requires a terminal prompt or --bootstrap-password-stdin: %w", err)
	}
	defer tty.Close()

	password, err := promptBootstrapPassword(tty, username)
	if err != nil {
		return bootstrapCredentials{}, err
	}
	return bootstrapCredentials{username: username, password: password}, nil
}

func readBootstrapPassword(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("install: read bootstrap password from stdin: %w", err)
	}
	data = bytes.TrimRight(data, "\r\n")
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("install: bootstrap password is empty")
	}
	if err := validateBootstrapPasswordLength(data); err != nil {
		return nil, err
	}
	return data, nil
}

func promptBootstrapPassword(tty *os.File, username string) ([]byte, error) {
	if _, err := fmt.Fprintf(tty, "First administrator username: %s\n", username); err != nil {
		return nil, fmt.Errorf("install: write bootstrap prompt: %w", err)
	}

	password, err := promptHiddenLine(tty, "First administrator password: ")
	if err != nil {
		return nil, err
	}
	confirm, err := promptHiddenLine(tty, "Confirm first administrator password: ")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(password, confirm) {
		return nil, fmt.Errorf("install: bootstrap passwords did not match")
	}
	if len(bytes.TrimSpace(password)) == 0 {
		return nil, fmt.Errorf("install: bootstrap password is empty")
	}
	if err := validateBootstrapPasswordLength(password); err != nil {
		return nil, err
	}
	return password, nil
}

func promptHiddenLine(tty *os.File, prompt string) ([]byte, error) {
	if _, err := io.WriteString(tty, prompt); err != nil {
		return nil, fmt.Errorf("install: write bootstrap prompt: %w", err)
	}
	if err := setTTYEcho(tty, false); err != nil {
		return nil, err
	}
	defer func() {
		_ = setTTYEcho(tty, true)
		_, _ = io.WriteString(tty, "\n")
	}()

	line, err := bufio.NewReader(tty).ReadBytes('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("install: read bootstrap password: %w", err)
	}
	return bytes.TrimRight(line, "\r\n"), nil
}

func setTTYEcho(tty *os.File, enabled bool) error {
	value := "echo"
	if !enabled {
		value = "-echo"
	}
	cmd := exec.Command("stty", value)
	cmd.Stdin = tty
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("install: configure terminal echo: %w", err)
	}
	return nil
}
