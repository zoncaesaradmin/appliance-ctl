package runtimeconfig

import "testing"

func TestValidateTargetArchitectureNormalizesHostNames(t *testing.T) {
	runtime := Selection{Package: "std-llm", InferenceEngine: "ollama", Architecture: "amd64"}
	if err := ValidateTargetArchitecture(runtime, "x86_64"); err != nil {
		t.Fatalf("expected x86_64 to match amd64: %v", err)
	}
	if err := ValidateTargetArchitecture(Selection{Package: "acc-llm", Architecture: "arm64"}, "amd64"); err == nil {
		t.Fatal("expected arm64 package to reject amd64 host")
	}
}

func TestValidateInference(t *testing.T) {
	standard := Selection{Package: "std-llm", InferenceEngine: "ollama", Architecture: "amd64"}
	if err := ValidateInference(standard); err != nil {
		t.Fatalf("standard amd64 runtime rejected: %v", err)
	}
	if RequiresGPU(standard) {
		t.Fatal("standard runtime must not require a GPU")
	}

	accelerated := Selection{Package: "acc-llm", InferenceEngine: "vllm", Architecture: "amd64"}
	if err := ValidateInference(accelerated); err != nil {
		t.Fatalf("accelerated amd64 runtime rejected: %v", err)
	}
	if !RequiresGPU(accelerated) {
		t.Fatal("accelerated runtime must require a GPU")
	}
	if err := ValidateTargetArchitecture(accelerated, "x86_64"); err != nil {
		t.Fatalf("accelerated amd64 runtime rejected on x86_64: %v", err)
	}

	arm := Selection{Package: "acc-llm", InferenceEngine: "vllm", Architecture: "arm64"}
	if err := ValidateInference(arm); err != nil {
		t.Fatalf("accelerated arm64 runtime rejected: %v", err)
	}
	if !RequiresGPU(arm) {
		t.Fatal("accelerated arm64 runtime must require a GPU")
	}
	if err := ValidateInference(Selection{Package: "std-llm", InferenceEngine: "ollama", Architecture: "arm64"}); err != nil {
		t.Fatalf("standard arm64 runtime rejected: %v", err)
	}
	if err := ValidateInference(Selection{Package: "std-llm-amd64", InferenceEngine: "ollama", Architecture: "amd64"}); err == nil {
		t.Fatal("legacy pack id must be rejected")
	}
}

func TestEqual(t *testing.T) {
	left := Selection{Package: "std-llm", InferenceEngine: "ollama", Architecture: "amd64"}
	right := Selection{Package: "std-llm", InferenceEngine: "ollama", Architecture: "amd64"}
	if !Equal(left, right) {
		t.Fatal("expected equal selections")
	}
	right.Architecture = "arm64"
	if Equal(left, right) {
		t.Fatal("architecture mismatch must not be equal")
	}
}

func equal(left, right Selection) bool { return Equal(left, right) }
