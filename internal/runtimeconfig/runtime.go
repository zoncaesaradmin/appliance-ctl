// Package runtimeconfig describes the implementation supplied by a signed
// delivery package. Capability names describe API availability, not engines.
package runtimeconfig

import (
	"fmt"
	"strings"
)

type Implementation struct {
	// InferenceEngine is the only package-owned runtime selector.
	// Product architecture is stamped from hostBaseline at assemble/install.
	InferenceEngine string `json:"inferenceEngine" yaml:"inferenceEngine"`
}

func Equal(left, right Selection) bool {
	return left.Package == right.Package && left.InferenceEngine == right.InferenceEngine &&
		left.Architecture == right.Architecture
}

type Selection struct {
	Package         string `json:"package" yaml:"package"`
	InferenceEngine string `json:"inferenceEngine" yaml:"inferenceEngine"`
	Architecture    string `json:"architecture" yaml:"architecture"`
}

// ValidateInference is the signed package/runtime contract boundary. The
// selected package still has to be present and architecture-compatible; a
// metadata declaration alone cannot provide an engine image.
//
// Product categories:
//   - standard (std-llm): Ollama; host CPU or GPU is chosen at runtime
//   - accelerated (acc-llm): vLLM; a usable GPU is required
//
// Architecture is the product TARGET_ARCH (amd64|arm64), not part of the pack ID.
func ValidateInference(runtime Selection) error {
	arch := normalizeArchitecture(runtime.Architecture)
	if arch != "amd64" && arch != "arm64" {
		return fmt.Errorf("unsupported inference runtime package=%q inferenceEngine=%q architecture=%q", runtime.Package, runtime.InferenceEngine, runtime.Architecture)
	}
	valid := runtime.Package == "std-llm" && runtime.InferenceEngine == "ollama" ||
		runtime.Package == "acc-llm" && runtime.InferenceEngine == "vllm"
	if !valid {
		return fmt.Errorf("unsupported inference runtime package=%q inferenceEngine=%q architecture=%q", runtime.Package, runtime.InferenceEngine, runtime.Architecture)
	}
	return nil
}

// RequiresGPU reports whether the selected package needs a usable GPU.
func RequiresGPU(runtime Selection) bool {
	return strings.EqualFold(strings.TrimSpace(runtime.InferenceEngine), "vllm")
}

// ValidateTargetArchitecture checks the selected product architecture against
// the machine that will run it. Bundle assembly deliberately does not call
// this: a build host may assemble a bundle for a different target architecture.
func ValidateTargetArchitecture(runtime Selection, targetArchitecture string) error {
	want := normalizeArchitecture(runtime.Architecture)
	have := normalizeArchitecture(targetArchitecture)
	if want == "" || have == "" || want != have {
		return fmt.Errorf("inference runtime package=%q targets architecture %q but install host is %q", runtime.Package, runtime.Architecture, targetArchitecture)
	}
	return nil
}

func NormalizeArchitecture(value string) string {
	return normalizeArchitecture(value)
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
