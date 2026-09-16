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

func TestValidateStandardAndAcceleratedRuntimes(t *testing.T) {
	standard := Selection{Package: "std-llm-amd64", InferenceEngine: "ollama", Architecture: "amd64"}
	if err := ValidateInference(standard); err != nil {
		t.Fatalf("standard runtime rejected: %v", err)
	}
	if RequiresGPU(standard) {
		t.Fatal("standard Ollama runtime must not require a GPU")
	}

	accelerated := Selection{Package: "acc-llm-amd64", InferenceEngine: "vllm", Architecture: "amd64"}
	if err := ValidateInference(accelerated); err != nil {
		t.Fatalf("accelerated amd64 runtime rejected: %v", err)
	}
	if !RequiresGPU(accelerated) {
		t.Fatal("accelerated vLLM runtime must require a GPU")
	}
	if err := ValidateTargetArchitecture(accelerated, "x86_64"); err != nil {
		t.Fatalf("accelerated amd64 runtime rejected on x86_64: %v", err)
	}

	arm := Selection{Package: "acc-llm-arm64", InferenceEngine: "vllm", Architecture: "arm64"}
	if err := ValidateInference(arm); err != nil {
		t.Fatalf("accelerated arm64 runtime rejected: %v", err)
	}
	if !RequiresGPU(arm) {
		t.Fatal("accelerated arm64 runtime must require a GPU")
	}
}

func TestEqualIgnoresAbsentModes(t *testing.T) {
	left := Selection{Package: "std-llm-amd64", InferenceEngine: "ollama", Architecture: "amd64"}
	right := Selection{Package: "std-llm-amd64", InferenceEngine: "ollama", Architecture: "amd64"}
	if !Equal(left, right) {
		t.Fatal("identical selections should compare equal")
	}
	right.Architecture = "arm64"
	if Equal(left, right) {
		t.Fatal("differing architecture should not compare equal")
	}
}
