package productconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	ProfileCore    = "core"
	ProfileBuilder = "builder"
	ProfileStorage = "storage"
)

var supportedProfiles = map[string]struct{}{
	ProfileCore:    {},
	ProfileBuilder: {},
	ProfileStorage: {},
}

func ResolveApplianceProfile(requested, current string) (string, error) {
	profile := strings.TrimSpace(requested)
	if profile == "" {
		profile = strings.TrimSpace(current)
	}
	if profile == "" {
		profile = ProfileCore
	}
	if _, ok := supportedProfiles[profile]; !ok {
		return "", fmt.Errorf("unknown appliance profile %q (supported: %s, %s, %s)", profile, ProfileCore, ProfileBuilder, ProfileStorage)
	}
	return profile, nil
}

func PrepareValuesFile(baseValuesPath, profile string) (string, func(), error) {
	effectiveProfile, err := ResolveApplianceProfile(profile, "")
	if err != nil {
		return "", func() {}, err
	}

	data, err := os.ReadFile(baseValuesPath)
	if err != nil {
		return "", func() {}, fmt.Errorf("product config: read values %s: %w", baseValuesPath, err)
	}

	var values map[string]any
	if err := yaml.Unmarshal(data, &values); err != nil {
		return "", func() {}, fmt.Errorf("product config: parse values %s: %w", baseValuesPath, err)
	}
	if values == nil {
		values = map[string]any{}
	}

	config, _ := values["config"].(map[string]any)
	if config == nil {
		config = map[string]any{}
	}
	config["applianceProfile"] = effectiveProfile
	values["config"] = config

	rendered, err := yaml.Marshal(values)
	if err != nil {
		return "", func() {}, fmt.Errorf("product config: render values override: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(baseValuesPath), ".zonctl-values-*.yaml")
	if err != nil {
		return "", func() {}, fmt.Errorf("product config: create temp values file: %w", err)
	}
	if _, err := tmp.Write(rendered); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", func() {}, fmt.Errorf("product config: write temp values file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", func() {}, fmt.Errorf("product config: close temp values file: %w", err)
	}

	cleanup := func() {
		_ = os.Remove(tmp.Name())
	}
	return tmp.Name(), cleanup, nil
}
