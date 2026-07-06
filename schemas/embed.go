// Package schemas embeds the versioned JSON Schema documents that define
// every structured document exchanged across the release pipeline and
// installer: release-input, release-manifest, installed-state, evidence,
// and CLI command results.
package schemas

import "embed"

//go:embed *.schema.json commands/*.schema.json
var FS embed.FS
