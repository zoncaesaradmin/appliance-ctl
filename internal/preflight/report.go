package preflight

import (
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/host"
)

// Check is one evaluated preflight finding, ready to serialize into an
// evidence.v1 report.
type Check struct {
	ID          string
	Category    string
	Status      Status
	Message     string
	Remediation string
	Timestamp   time.Time
	DurationMs  int64
}

// Run evaluates every registered check against facts. Evaluation is pure
// and read-only; it does not re-detect facts or touch the host.
func Run(facts host.Facts) []Check {
	checks := make([]Check, 0, len(checkDefs))
	for _, def := range checkDefs {
		start := time.Now()
		r := def.Eval(facts)
		checks = append(checks, Check{
			ID:          def.ID,
			Category:    def.Category,
			Status:      r.Status,
			Message:     r.Message,
			Remediation: r.Remediation,
			Timestamp:   start.UTC(),
			DurationMs:  time.Since(start).Milliseconds(),
		})
	}
	return checks
}

// statusPriority orders statuses from most to least severe for
// OverallStatus aggregation.
var statusPriority = map[Status]int{
	StatusUnsupported:    0,
	StatusOperatorAction: 1,
	StatusAutoFix:        2,
	StatusPass:           3,
}

// OverallStatus reports the most severe status across all checks, per the
// Host Preflight Policy classification.
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

// BuildReport marshals checks into an evidence.v1 document and validates
// it against schemas/evidence.v1.schema.json before returning, so a
// non-conforming report is a build-time test failure, not a support-bundle
// surprise.
func BuildReport(checks []Check, applianceVersion, reportID string, generatedAt time.Time) ([]byte, error) {
	evChecks := make([]evidence.Check, 0, len(checks))
	for _, c := range checks {
		evChecks = append(evChecks, evidence.Check{
			ID:          c.ID,
			Category:    c.Category,
			Status:      evidence.Status(c.Status),
			Message:     c.Message,
			Remediation: c.Remediation,
			Timestamp:   c.Timestamp,
			DurationMs:  c.DurationMs,
			// Preflight checks only ever read host facts; there is
			// nothing to re-run differently and nothing secret to redact.
			Idempotent:      true,
			SecretsRedacted: true,
		})
	}

	return evidence.BuildReport("preflight", applianceVersion, reportID, evChecks, generatedAt)
}
