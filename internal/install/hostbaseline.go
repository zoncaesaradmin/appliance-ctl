package install

import (
	"fmt"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/bundle"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/host"
)

// CheckBundleHostBaseline returns the exact host-vs-bundle baseline evidence
// check used by both install and upgrade. The appliance fails closed when the
// current host does not match the signed bundle baseline exactly.
func CheckBundleHostBaseline(facts host.Facts, baseline bundle.HostBaseline) evidence.Check {
	check := evidence.Check{
		ID:              "bundle-host-baseline-match",
		Category:        "host",
		Timestamp:       time.Now().UTC(),
		Idempotent:      true,
		SecretsRedacted: true,
	}
	if strings.TrimSpace(facts.OS) == strings.TrimSpace(baseline.OS) &&
		strings.TrimSpace(facts.OSVersion) == strings.TrimSpace(baseline.OSVersion) &&
		strings.TrimSpace(facts.Arch) == strings.TrimSpace(baseline.Arch) {
		check.Status = evidence.StatusPass
		check.Message = fmt.Sprintf(
			"host %s %s (%s) matches bundle baseline %s %s (%s)",
			facts.OS, facts.OSVersion, facts.Arch,
			baseline.OS, baseline.OSVersion, baseline.Arch,
		)
		return check
	}
	check.Status = evidence.StatusUnsupported
	check.Message = fmt.Sprintf(
		"host %s %s (%s) does not match bundle baseline %s %s (%s)",
		strings.TrimSpace(facts.OS), strings.TrimSpace(facts.OSVersion), strings.TrimSpace(facts.Arch),
		strings.TrimSpace(baseline.OS), strings.TrimSpace(baseline.OSVersion), strings.TrimSpace(baseline.Arch),
	)
	return check
}
