package runtimeconfig

import "testing"

func TestValidateTargetArchitectureNormalizesHostNames(t *testing.T) {
	runtime := Selection{Package: "std-llm-amd64", InferenceEngine: "ollama", Architecture: "amd64", SupportedModes: []string{"cpu"}}
	if err := ValidateTargetArchitecture(runtime, "x86_64"); err != nil {
		t.Fatalf("expected x86_64 to match amd64: %v", err)
	}
	if err := ValidateTargetArchitecture(Selection{Package: "acc-llm-arm64", Architecture: "arm64"}, "amd64"); err == nil {
		t.Fatal("expected architecture mismatch")
	}
}

func TestLegacyStandardRuntimeDefaultsToCPU(t *testing.T) {
	legacy := Selection{Package: "std-llm-amd64", InferenceEngine: "ollama", Architecture: "amd64"}
	if err := ValidateInference(legacy); err != nil {
		t.Fatalf("legacy standard runtime rejected: %v", err)
	}
	if modes := EffectiveModes(legacy); len(modes) != 1 || modes[0] != "cpu" {
		t.Fatalf("effective modes = %v", modes)
	}
	current := legacy
	current.SupportedModes = []string{"cpu"}
	if !Equal(legacy, current) {
		t.Fatal("legacy and explicit standard CPU selections should compare equal")
	}
}

func TestValidateVLLMAMD64CPU(t *testing.T) {
	runtime := Selection{Package: "acc-llm-amd64", InferenceEngine: "vllm", Architecture: "amd64", SupportedModes: []string{"cpu"}}
	if err := ValidateInference(runtime); err != nil {
		t.Fatalf("vLLM amd64 CPU runtime rejected: %v", err)
	}
	if err := ValidateTargetArchitecture(runtime, "x86_64"); err != nil {
		t.Fatalf("vLLM amd64 runtime rejected on x86_64: %v", err)
	}
}
