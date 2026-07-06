// Package preflight evaluates read-only host checks against the qualified
// v1 host baseline (Ubuntu Server 22.04/24.04 LTS, amd64, local ext4
// storage) and assembles the results into an evidence.v1-schema-valid
// report. It never mutates host state; see docs/release-plan.md Host
// Preflight Policy.
package preflight

const (
	// SupportedOS and SupportedArch pin the v1 host baseline. Additional
	// platforms require their own qualification and a new baseline
	// constant, not a relaxation of this one.
	SupportedOS   = "ubuntu"
	SupportedArch = "amd64"

	SupportedFilesystem = "ext4"

	// Resource minimums. These are the initial v1 baseline figures; they
	// may be revised as product sizing guidance from appliance-code lands,
	// but a value must be pinned here for preflight to be well-defined.
	MinCPUCount          = 4
	MinMemoryBytes       = 8 * 1024 * 1024 * 1024  // 8 GiB
	MinDataDirFreeBytes  = 50 * 1024 * 1024 * 1024 // 50 GiB
	MinDataDirFreeInodes = 200_000
)

// SupportedOSVersions lists every qualified Ubuntu Server LTS version.
// Additional versions require their own qualification evidence.
var SupportedOSVersions = []string{"22.04", "24.04"}

// RequiredPorts lists the ports a single-node K3s baseline needs free.
// Product-specific application ports are added once appliance-code's
// configuration schema pins them (see Repository Boundary in the plan).
var RequiredPorts = []int{6443, 10250, 8472}

func isSupportedOSVersion(version string) bool {
	for _, v := range SupportedOSVersions {
		if v == version {
			return true
		}
	}
	return false
}
