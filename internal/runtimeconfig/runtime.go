// Package runtimeconfig describes the implementation supplied by a signed
// delivery package. Capability names describe API availability, not engines.
package runtimeconfig

import (
	"fmt"
	"strings"
)

type Implementation struct {
	InferenceEngine string `json:"inferenceEngine" yaml:"inferenceEngine"`
	Architecture    string `json:"architecture" yaml:"architecture"`
}

type Selection struct {
	Package         string `json:"package" yaml:"package"`
	InferenceEngine string `json:"inferenceEngine" yaml:"inferenceEngine"`
	Architecture    string `json:"architecture" yaml:"architecture"`
}

// ValidateInference is the installed engine support boundary. A future engine
// must implement its chart, offline hardware setup, and model lifecycle before
// adding support here. A metadata declaration alone cannot enable a backend.
func ValidateInference(runtime Selection) error {
	if runtime.Package != "std-llm-amd64" || runtime.InferenceEngine != "ollama" || runtime.Architecture != "amd64" {
		return fmt.Errorf("unsupported inference runtime package=%q inferenceEngine=%q architecture=%q", runtime.Package, runtime.InferenceEngine, runtime.Architecture)
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
