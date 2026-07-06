package preflight_test

import (
	"testing"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/preflight"
)

func TestBuildReport_ValidatesAgainstEvidenceSchema(t *testing.T) {
	checks := preflight.Run(baseFacts())

	data, err := preflight.BuildReport(checks, "2.4.0", "evidence-test-001", time.Now())
	if err != nil {
		t.Fatalf("BuildReport returned an error, meaning the report does not satisfy evidence.v1: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty report bytes")
	}
}

func TestBuildReport_RemediationCarriedForOperatorAction(t *testing.T) {
	facts := baseFacts()
	facts.CPUCount = 1 // forces cpu-count-min into operator-action, which requires remediation

	checks := preflight.Run(facts)
	if _, err := preflight.BuildReport(checks, "2.4.0", "evidence-test-002", time.Now()); err != nil {
		t.Fatalf("expected operator-action check with remediation to satisfy schema, got: %v", err)
	}
}

// Regression: every non-Linux-host fallback branch (facts.KernelRelease
// == "") reports StatusUnsupported and must carry non-empty remediation,
// since evidence.v1 requires it for operator-action/unsupported checks.
// This was missed by TestChecks_NonLinuxSignalsReportUnsupported, which
// only inspected Check.Status directly instead of round-tripping through
// BuildReport's schema validation.
func TestBuildReport_NonLinuxHostChecksSatisfySchema(t *testing.T) {
	facts := baseFacts()
	facts.KernelRelease = ""

	checks := preflight.Run(facts)
	if _, err := preflight.BuildReport(checks, "2.4.0", "evidence-test-003", time.Now()); err != nil {
		t.Fatalf("expected non-Linux-host checks to satisfy the evidence schema, got: %v", err)
	}
}
