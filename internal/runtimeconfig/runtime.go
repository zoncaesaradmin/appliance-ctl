// Package runtimeconfig describes the implementation supplied by a signed
// delivery package. Capability names describe API availability, not engines.
package runtimeconfig

import (
	"fmt"
	"slices"
	"strings"
)

type Implementation struct {
	InferenceEngine string   `json:"inferenceEngine" yaml:"inferenceEngine"`
	Architecture    string   `json:"architecture" yaml:"architecture"`
	SupportedModes  []string `json:"supportedModes" yaml:"supportedModes"`
}

func Equal(left, right Selection) bool {
	left.SupportedModes = EffectiveModes(left)
	right.SupportedModes = EffectiveModes(right)
	return left.Package == right.Package && left.InferenceEngine == right.InferenceEngine &&
		left.Architecture == right.Architecture && slices.Equal(left.SupportedModes, right.SupportedModes)
}

// EffectiveModes preserves install/upgrade compatibility with manifests from
// before supportedModes was added to the v1 schema. Only the already-shipped
// standard Ollama package has an implicit legacy value.
func EffectiveModes(selection Selection) []string {
	if len(selection.SupportedModes) > 0 {
		return append([]string(nil), selection.SupportedModes...)
	}
	if selection.Package == "std-llm-amd64" && selection.InferenceEngine == "ollama" {
		return []string{"cpu"}
	}
	return nil
}

type Selection struct {
	Package         string   `json:"package" yaml:"package"`
	InferenceEngine string   `json:"inferenceEngine" yaml:"inferenceEngine"`
	Architecture    string   `json:"architecture" yaml:"architecture"`
	SupportedModes  []string `json:"supportedModes" yaml:"supportedModes"`
}

// ValidateInference is the signed package/runtime contract boundary. The
// selected package still has to be present and architecture-compatible; a
// metadata declaration alone cannot provide an engine image.
func ValidateInference(runtime Selection) error {
	valid := runtime.Package == "std-llm-amd64" && runtime.InferenceEngine == "ollama" && runtime.Architecture == "amd64" ||
		runtime.Package == "acc-llm-amd64" && runtime.InferenceEngine == "vllm" && runtime.Architecture == "amd64" ||
		runtime.Package == "acc-llm-arm64" && runtime.InferenceEngine == "vllm" && runtime.Architecture == "arm64"
	if !valid {
		return fmt.Errorf("unsupported inference runtime package=%q inferenceEngine=%q architecture=%q", runtime.Package, runtime.InferenceEngine, runtime.Architecture)
	}
	if err := ValidateModes(EffectiveModes(runtime)); err != nil {
		return fmt.Errorf("inference runtime package=%q: %w", runtime.Package, err)
	}
	return nil
}

func ValidateModes(modes []string) error {
	if len(modes) == 0 {
		return fmt.Errorf("supportedModes must not be empty")
	}
	seen := map[string]bool{}
	for _, mode := range modes {
		mode = strings.ToLower(strings.TrimSpace(mode))
		if mode != "cpu" && mode != "cuda" {
			return fmt.Errorf("unsupported inference mode %q", mode)
		}
		if seen[mode] {
			return fmt.Errorf("duplicate inference mode %q", mode)
		}
		seen[mode] = true
	}
	return nil
}

// ValidateTargetArchitecture checks the selected package against the machine
// that will run it. Bundle assembly deliberately does not call this: a build
// host may assemble a bundle for a different target architecture.
func ValidateTargetArchitecture(runtime Selection, targetArchitecture string) error {
	want := normalizeArchitecture(runtime.Architecture)
	have := normalizeArchitecture(targetArchitecture)
	if want == "" || have == "" || want != have {
		return fmt.Errorf("inference runtime package=%q targets architecture %q but install host is %q", runtime.Package, runtime.Architecture, targetArchitecture)
	}
	return nil
}

func normalizeArchitecture(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "x86_64", "x86-64":
		return "amd64"
	case "aarch64":
		return "arm64"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}
