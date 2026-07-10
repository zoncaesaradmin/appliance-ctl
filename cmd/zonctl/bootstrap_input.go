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
