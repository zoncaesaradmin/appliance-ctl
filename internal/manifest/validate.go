// Package manifest validates the release pipeline's structured documents
// (release-input, release-manifest, installed-state, evidence, and CLI
// command results) against their versioned JSON Schemas.
package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/zoncaesaradmin/appliance-ctl/schemas"
)

// Kind identifies one of the release pipeline's structured document types.
type Kind string

const (
	KindReleaseInput    Kind = "release-input"
	KindReleaseManifest Kind = "release-manifest"
	KindInstalledState  Kind = "installed-state"
	KindEvidence        Kind = "evidence"
	KindCommandResult   Kind = "command-result"
)

var schemaPaths = map[Kind]string{
	KindReleaseInput:    "release-input.v1.schema.json",
	KindReleaseManifest: "release-manifest.v1.schema.json",
	KindInstalledState:  "installed-state.v1.schema.json",
	KindEvidence:        "evidence.v1.schema.json",
	KindCommandResult:   "commands/command-result.v1.schema.json",
}

const schemaBaseURI = "https://appliance-release/schemas/"

// Compile loads and compiles the JSON Schema for the given document kind.
func Compile(kind Kind) (*jsonschema.Schema, error) {
	path, ok := schemaPaths[kind]
	if !ok {
		return nil, fmt.Errorf("manifest: unknown schema kind %q", kind)
	}

	data, err := schemas.FS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("manifest: read schema %q: %w", path, err)
	}

	c := jsonschema.NewCompiler()
	c.Draft = jsonschema.Draft2020
	schemaURI := schemaBaseURI + path
	if err := c.AddResource(schemaURI, bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("manifest: add schema resource %q: %w", path, err)
	}

	sch, err := c.Compile(schemaURI)
	if err != nil {
		return nil, fmt.Errorf("manifest: compile schema %q: %w", path, err)
	}
	return sch, nil
}

// Validate decodes doc as JSON and validates it against the schema for kind.
func Validate(kind Kind, doc []byte) error {
	sch, err := Compile(kind)
	if err != nil {
		return err
	}

	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return fmt.Errorf("manifest: decode document: %w", err)
	}

	if err := sch.Validate(v); err != nil {
		return fmt.Errorf("manifest: document does not satisfy %s schema: %w", kind, err)
	}
	return nil
}
