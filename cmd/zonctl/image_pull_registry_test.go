package main

import (
	"os"
	"testing"
)

func TestResolveImagePullRegistry_OptionalEmpty(t *testing.T) {
	cfg, err := resolveImagePullRegistry(cliOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Registry != "" {
		t.Fatalf("expected empty registry, got %q", cfg.Registry)
	}
}

func TestResolveImagePullRegistry_RequiresEnvNames(t *testing.T) {
	_, err := resolveImagePullRegistry(cliOptions{imagePullRegistry: "reg.example"}, nil)
	if err == nil {
		t.Fatal("expected error when env names missing")
	}
}

func TestResolveImagePullRegistry_FromEnv(t *testing.T) {
	t.Setenv("TEST_PULL_USER", "admin")
	t.Setenv("TEST_PULL_TOKEN", "tok")
	t.Setenv("TEST_PULL_TLS", "false")
	cfg, err := resolveImagePullRegistry(cliOptions{
		imagePullRegistry:             "artifact-dns-1.appliance.internal",
		imagePullRegistryUsernameEnv:  "TEST_PULL_USER",
		imagePullRegistryTokenEnv:     "TEST_PULL_TOKEN",
		imagePullRegistryTLSVerifyEnv: "TEST_PULL_TLS",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Registry != "artifact-dns-1.appliance.internal" || cfg.Username != "admin" || cfg.Password != "tok" || cfg.TLSVerify {
		t.Fatalf("unexpected cfg: %+v", cfg)
	}
	_ = os.Getenv // keep os import used if Setenv alone isn't enough on older go
}
