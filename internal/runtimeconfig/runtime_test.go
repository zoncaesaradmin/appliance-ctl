package runtimeconfig

import "testing"

func TestValidateTargetArchitectureNormalizesHostNames(t *testing.T) {
	runtime := Selection{Package: "std-llm-amd64", InferenceEngine: "ollama", Architecture: "amd64"}
	if err := ValidateTargetArchitecture(runtime, "x86_64"); err != nil {
		t.Fatalf("expected x86_64 to match amd64: %v", err)
	}
	if err := ValidateTargetArchitecture(Selection{Package: "acc-llm-arm64", Architecture: "arm64"}, "amd64"); err == nil {
		t.Fatal("expected architecture mismatch")
	}
}
