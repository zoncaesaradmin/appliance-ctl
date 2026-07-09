// Package evidence assembles machine-readable check results from any
// operation (preflight, verification, conformance, ...) into an
// evidence.v1-schema-valid report, and validates the result before
// returning it.
package evidence

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/manifest"
)

// nonKebabRun matches any run of characters not allowed inside an
// evidence.v1 check ID segment (schemas/evidence.v1.schema.json pins
// ^[a-z][a-z0-9]*(-[a-z0-9]+)*$).
var nonKebabRun = regexp.MustCompile(`[^a-z0-9]+`)

// SanitizeIDSegment converts an arbitrary, externally-sourced string (an
// image reference, a file path, a CVE ID, ...) into a value safe to embed
// in an evidence.v1 check ID: lowercased, every run of non-[a-z0-9]
// characters collapsed to a single hyphen, and leading/trailing hyphens
// trimmed. Every check ID built by concatenating a literal prefix with a
// dynamic name or path MUST sanitize that dynamic part first — none of
// image references (contain "/" and ":"), file paths (contain "/" and
// "."), or CVE-style IDs (contain uppercase letters) are valid check-ID
// characters on their own, and a raw concatenation fails schema
// validation for the whole report, not just one check.
func SanitizeIDSegment(s string) string {
	s = strings.ToLower(s)
	s = nonKebabRun.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "unknown"
	}
	return s
}

// Status mirrors the full evidence.v1 check status enum.
type Status string

const (
	StatusPass           Status = "pass"
	StatusAutoFix        Status = "auto-fix"
	StatusOperatorAction Status = "operator-action"
	StatusUnsupported    Status = "unsupported"
	StatusFail           Status = "fail"
	StatusSkipped        Status = "skipped"
)

// Check is one evaluated finding, ready to serialize into an evidence.v1
// report.
type Check struct {
	ID              string
	Category        string
	Status          Status
	Message         string
	Remediation     string
	Timestamp       time.Time
	DurationMs      int64
	Idempotent      bool
	SecretsRedacted bool
}

// statusPriority orders statuses from most to least severe for
// OverallStatus aggregation, across the full evidence.v1 enum.
var statusPriority = map[Status]int{
	StatusFail:           0,
	StatusUnsupported:    1,
	StatusOperatorAction: 2,
	StatusAutoFix:        3,
	StatusSkipped:        4,
	StatusPass:           5,
}

// OverallStatus reports the most severe status across all checks.
func OverallStatus(checks []Check) Status {
	overall := StatusPass
	best := statusPriority[StatusPass]
	for _, c := range checks {
		if p, ok := statusPriority[c.Status]; ok && p < best {
			best = p
			overall = c.Status
		}
	}
	return overall
}

type reportDoc struct {
	SchemaVersion    int        `json:"schemaVersion"`
	ReportID         string     `json:"reportId"`
	GeneratedAt      string     `json:"generatedAt"`
	ApplianceVersion string     `json:"applianceVersion"`
	Operation        string     `json:"operation"`
	Checks           []checkDoc `json:"checks"`
}

type checkDoc struct {
	ID              string `json:"id"`
	Category        string `json:"category"`
	Status          string `json:"status"`
	Message         string `json:"message"`
	Remediation     string `json:"remediation,omitempty"`
	Timestamp       string `json:"timestamp"`
	DurationMs      int64  `json:"durationMs"`
	Idempotent      bool   `json:"idempotent"`
	SecretsRedacted bool   `json:"secretsRedacted"`
}

// BuildReport marshals checks into an evidence.v1 document for the given
// operation and validates it against schemas/evidence.v1.schema.json
// before returning, so a non-conforming report is a build-time test
// failure, not a support-bundle surprise.
func BuildReport(operation, applianceVersion, reportID string, checks []Check, generatedAt time.Time) ([]byte, error) {
	doc := reportDoc{
		SchemaVersion:    1,
		ReportID:         reportID,
		GeneratedAt:      generatedAt.UTC().Format(time.RFC3339),
		ApplianceVersion: applianceVersion,
		Operation:        operation,
		Checks:           make([]checkDoc, 0, len(checks)),
	}

	for _, c := range checks {
		doc.Checks = append(doc.Checks, checkDoc{
			ID:              c.ID,
			Category:        c.Category,
			Status:          string(c.Status),
			Message:         c.Message,
			Remediation:     c.Remediation,
			Timestamp:       c.Timestamp.UTC().Format(time.RFC3339),
			DurationMs:      c.DurationMs,
			Idempotent:      c.Idempotent,
			SecretsRedacted: c.SecretsRedacted,
		})
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("evidence: marshal report: %w", err)
	}

	if err := manifest.Validate(manifest.KindEvidence, data); err != nil {
		return nil, fmt.Errorf("evidence: assembled report failed schema validation: %w", err)
	}

	return data, nil
}
