// Package runtimeconfig describes the implementation supplied by a signed
// delivery package. Capability names describe API availability, not engines.
package runtimeconfig

import "fmt"

type Implementation struct {
	Engine string `json:"engine" yaml:"engine"`
}

type Selection struct {
	Package string `json:"package" yaml:"package"`
	Engine  string `json:"engine" yaml:"engine"`
}

// ValidateInference is the installed engine support boundary. A future engine
// must implement its chart, offline hardware setup, and model lifecycle before
// adding support here. A metadata declaration alone cannot enable a backend.
func ValidateInference(runtime Selection) error {
	if runtime.Package != "std-llm-amd64" || runtime.Engine != "ollama" {
		return fmt.Errorf("unsupported inference runtime package=%q engine=%q", runtime.Package, runtime.Engine)
	}
	return nil
}
