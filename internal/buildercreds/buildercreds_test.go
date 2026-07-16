package buildercreds

import (
	"testing"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
)

func TestNewCheck_SatisfiesEvidenceSchema(t *testing.T) {
	check := newCheck("builder-source-key-default")
	check.Status = evidence.StatusPass
	check.Message = "builder source keypair ready"

	if _, err := evidence.BuildReport("install", "0.1.0", "evidence-test-buildercreds", []evidence.Check{check}, time.Now()); err != nil {
		t.Fatalf("expected builder credential checks to satisfy the evidence schema, got: %v", err)
	}
}
