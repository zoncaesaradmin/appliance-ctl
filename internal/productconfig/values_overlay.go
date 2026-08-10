package productconfig

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// PrepareValuesOverlayFile merges overlay into an optional base values file and
// writes the result to a new temp file for one rollout slice.
func PrepareValuesOverlayFile(baseValuesPath string, overlay map[string]any) (string, func(), error) {
	values := map[string]any{}
	if baseValuesPath != "" {
		data, err := os.ReadFile(baseValuesPath)
		if err != nil {
			return "", func() {}, fmt.Errorf("product config: read values %s: %w", baseValuesPath, err)
		}
		if err := yaml.Unmarshal(data, &values); err != nil {
			return "", func() {}, fmt.Errorf("product config: parse values %s: %w", baseValuesPath, err)
		}
		if values == nil {
			values = map[string]any{}
		}
	}
	mergeValues(values, overlay)

	rendered, err := yaml.Marshal(values)
	if err != nil {
		return "", func() {}, fmt.Errorf("product config: render values overlay: %w", err)
	}

	tempDir := os.TempDir()
	if baseValuesPath != "" {
		tempDir = filepath.Dir(baseValuesPath)
	}
	tmp, err := os.CreateTemp(tempDir, ".zonctl-values-overlay-*.yaml")
	if err != nil {
		return "", func() {}, fmt.Errorf("product config: create temp overlay values file: %w", err)
	}
	if _, err := tmp.Write(rendered); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", func() {}, fmt.Errorf("product config: write temp overlay values file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", func() {}, fmt.Errorf("product config: close temp overlay values file: %w", err)
	}
	cleanup := func() {
		_ = os.Remove(tmp.Name())
	}
	return tmp.Name(), cleanup, nil
}

func mergeValues(dst, src map[string]any) {
	for key, value := range src {
		srcMap, srcIsMap := value.(map[string]any)
		if !srcIsMap {
			dst[key] = value
			continue
		}
		dstMap, ok := dst[key].(map[string]any)
		if !ok || dstMap == nil {
			dstMap = map[string]any{}
			dst[key] = dstMap
		}
		mergeValues(dstMap, srcMap)
	}
}
