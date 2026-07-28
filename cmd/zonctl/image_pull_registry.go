package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/zoncaesaradmin/appliance-ctl/internal/k3s"
	"github.com/zoncaesaradmin/appliance-ctl/internal/redact"
)

// resolveImagePullRegistry builds optional K3s registries config from CLI
// flags. Credentials come from env vars named by the *-env flags so the
// same DEV_REGISTRY_* names used for build/publish can be reused.
func resolveImagePullRegistry(opts cliOptions, redactor *redact.Redactor) (k3s.RegistriesConfig, error) {
	host := strings.TrimSpace(opts.imagePullRegistry)
	if host == "" {
		return k3s.RegistriesConfig{}, nil
	}
	userEnv := strings.TrimSpace(opts.imagePullRegistryUsernameEnv)
	tokenEnv := strings.TrimSpace(opts.imagePullRegistryTokenEnv)
	if userEnv == "" || tokenEnv == "" {
		return k3s.RegistriesConfig{}, fmt.Errorf("image pull registry %q requires --image-pull-registry-username-env and --image-pull-registry-token-env", host)
	}
	username := strings.TrimSpace(os.Getenv(userEnv))
	password := strings.TrimSpace(os.Getenv(tokenEnv))
	if username == "" {
		return k3s.RegistriesConfig{}, fmt.Errorf("image pull registry username env %q is empty", userEnv)
	}
	if password == "" {
		return k3s.RegistriesConfig{}, fmt.Errorf("image pull registry token env %q is empty", tokenEnv)
	}
	if redactor != nil {
		redactor.Register(password)
	}

	tlsVerify := true
	if tlsEnv := strings.TrimSpace(opts.imagePullRegistryTLSVerifyEnv); tlsEnv != "" {
		raw := strings.TrimSpace(os.Getenv(tlsEnv))
		if raw == "" {
			return k3s.RegistriesConfig{}, fmt.Errorf("image pull registry TLS verify env %q is empty", tlsEnv)
		}
		switch strings.ToLower(raw) {
		case "1", "true", "yes", "on":
			tlsVerify = true
		case "0", "false", "no", "off":
			tlsVerify = false
		default:
			return k3s.RegistriesConfig{}, fmt.Errorf("image pull registry TLS verify env %q must be true or false (got %q)", tlsEnv, raw)
		}
	}

	cfg := k3s.RegistriesConfig{
		Registry:  host,
		Username:  username,
		Password:  password,
		TLSVerify: tlsVerify,
	}
	if err := cfg.Validate(); err != nil {
		return k3s.RegistriesConfig{}, err
	}
	return cfg, nil
}
