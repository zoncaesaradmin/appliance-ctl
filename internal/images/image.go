// Package images preloads every bundled OCI image into the K3s
// (containerd) image store from local archives, so "no image pull can
// fall through to a public registry" and the appliance's own zot
// instance is never a bootstrap dependency (see docs/release-plan.md).
package images

import "sort"

// Category fixes the required preload order: K3s's own platform images
// first (CoreDNS, Traefik, ...), then this appliance's dependencies
// (zot, Argo controller/executor), then the product's application
// images. Preloading platform images first means K3s never needs to
// pull anything itself on first start.
type Category int

const (
	CategoryK3sPlatform Category = iota
	CategoryDependency
	CategoryApplication
)

// Image is one OCI image archive to import, already digest/signature
// verified by internal/verify before this package ever sees it.
type Image struct {
	Name           string // the image reference, e.g. "docker.io/rancher/mirrored-coredns-coredns:1.11.3"
	ArchivePath    string // local path to the OCI tar in the bundle
	ExpectedDigest string // "sha256:<hex>" of the archive file
	Category       Category
}

// Ordered returns images sorted by Category (K3s platform, then
// dependency, then application), preserving relative order within each
// category so a stable, deterministic import sequence results regardless
// of the input order.
func Ordered(images []Image) []Image {
	sorted := make([]Image, len(images))
	copy(sorted, images)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Category < sorted[j].Category
	})
	return sorted
}
