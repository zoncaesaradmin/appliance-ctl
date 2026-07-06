// Package upgrade implements the N-1 upgrade sequence: verifying the
// target release is compatible with what's installed, taking a mandatory
// pre-upgrade backup, staging and applying the new K3s/CRDs/chart, and
// falling back to a restore-based rollback on failure. See "Upgrade
// Sequence" in docs/release-plan.md.
package upgrade

import (
	"strconv"
	"strings"
)

// compareVersions compares two "major.minor.patch[-pre]" version strings,
// returning -1 if a < b, 0 if equal, 1 if a > b. It compares numeric
// major/minor/patch components; any unparseable component falls back to
// a plain string comparison so this never panics on unexpected input.
func compareVersions(a, b string) int {
	aParts := splitVersion(a)
	bParts := splitVersion(b)

	for i := 0; i < 3; i++ {
		an, aok := aParts[i]
		bn, bok := bParts[i]
		if !aok || !bok {
			return strings.Compare(a, b)
		}
		if an != bn {
			if an < bn {
				return -1
			}
			return 1
		}
	}
	return 0
}

// splitVersion parses up to the first three dot-separated numeric
// components of a version string (ignoring any "-prerelease" suffix).
func splitVersion(v string) map[int]int {
	v = strings.SplitN(v, "-", 2)[0]
	fields := strings.Split(v, ".")

	out := map[int]int{}
	for i := 0; i < 3 && i < len(fields); i++ {
		n, err := strconv.Atoi(fields[i])
		if err != nil {
			return out
		}
		out[i] = n
	}
	return out
}

// isDowngrade reports whether target is an older version than current.
func isDowngrade(current, target string) bool {
	return compareVersions(target, current) < 0
}

// isSupportedSource reports whether installedVersion appears in the
// release's declared list of upgradeable-from versions (the N-1 policy).
func isSupportedSource(installedVersion string, supported []string) bool {
	for _, v := range supported {
		if v == installedVersion {
			return true
		}
	}
	return false
}
