package images

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// BundledImageTag is the tag-form annotation written into OCI archives so
// containerd's ctr import registers a stable local name. Digest-pinned refs
// (name@sha256:...) are applied afterward with `ctr image tag`, because ctr
// often ignores or mishandles digest-form org.opencontainers.image.ref.name
// values and falls back to import-DATE@sha256:... names that CRI cannot use.
const BundledImageTag = "bundled"

// OCIArchiveInfo is the content digest and optional ref annotation from an
// OCI-layout archive's index.json.
type OCIArchiveInfo struct {
	ManifestDigest string // sha256:<hex>
	AnnotationRef  string
}

// ReadOCIArchiveInfo reads index.json from an OCI-layout tar. Non-OCI archives
// return ok=false.
func ReadOCIArchiveInfo(archivePath string) (OCIArchiveInfo, bool, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return OCIArchiveInfo{}, false, fmt.Errorf("images: open archive %s: %w", archivePath, err)
	}
	defer f.Close()

	tr := tar.NewReader(f)
	var indexRaw []byte
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return OCIArchiveInfo{}, false, nil
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if name == "index.json" {
			indexRaw, err = io.ReadAll(io.LimitReader(tr, 1<<20))
			if err != nil {
				return OCIArchiveInfo{}, false, fmt.Errorf("images: read index.json from %s: %w", archivePath, err)
			}
			break
		}
	}
	if indexRaw == nil {
		return OCIArchiveInfo{}, false, nil
	}

	var index struct {
		Manifests []struct {
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(indexRaw, &index); err != nil {
		return OCIArchiveInfo{}, false, fmt.Errorf("images: parse index.json from %s: %w", archivePath, err)
	}
	if len(index.Manifests) == 0 {
		return OCIArchiveInfo{}, false, fmt.Errorf("images: archive %s has no manifests in index.json", archivePath)
	}
	chosen := index.Manifests[0]
	return OCIArchiveInfo{
		ManifestDigest: strings.TrimSpace(chosen.Digest),
		AnnotationRef:  strings.TrimSpace(chosen.Annotations["org.opencontainers.image.ref.name"]),
	}, true, nil
}

// ValidateOCIArchiveReference checks that an OCI-layout archive's manifest
// digest matches the digest embedded in expectedRef (when digest-pinned).
// The archive annotation may be the digest-pinned ref or the tag-form
// local name (registry.local/<name>:bundled) used for reliable ctr import.
//
// Contract with appliance-release packaging:
//
//	annotation: registry.local/<name>:bundled
//	imageReference / expectedRef: registry.local/<name>@sha256:<platform-manifest-digest>
//
// Install then runs `ctr image tag` to create expectedRef from imported content.
func ValidateOCIArchiveReference(archivePath, expectedRef string) error {
	expectedRef = strings.TrimSpace(expectedRef)
	if expectedRef == "" {
		return fmt.Errorf("images: expected image reference is empty")
	}
	expectedDigest, digestPinned := digestFromImageRef(expectedRef)
	if !digestPinned {
		return nil
	}

	info, ok, err := ReadOCIArchiveInfo(archivePath)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if info.ManifestDigest != expectedDigest {
		return fmt.Errorf(
			"images: archive %s manifest digest %s does not match expected reference digest %s (%s); rebuild/export so the archived platform manifest digest matches the bundle imageReference",
			archivePath, info.ManifestDigest, expectedDigest, expectedRef,
		)
	}
	if info.AnnotationRef == "" {
		return nil
	}
	if annotationCompatibleWithRef(info.AnnotationRef, expectedRef, expectedDigest) {
		return nil
	}
	return fmt.Errorf(
		"images: archive %s annotation ref %q is incompatible with expected reference %q (accepts digest pin, %s, or %s:%s)",
		archivePath, info.AnnotationRef, expectedRef, imageRefLocalName(expectedRef), imageRefLocalName(expectedRef), BundledImageTag,
	)
}

func annotationCompatibleWithRef(annotation, expectedRef, expectedDigest string) bool {
	annotation = strings.TrimSpace(annotation)
	expectedRef = strings.TrimSpace(expectedRef)
	if annotation == expectedRef {
		return true
	}
	if annDigest, ok := digestFromImageRef(annotation); ok {
		return annDigest == expectedDigest
	}
	localName := imageRefLocalName(expectedRef)
	if annotation == localName || annotation == localName+":"+BundledImageTag {
		return true
	}
	if strings.HasPrefix(annotation, localName+":") && !strings.Contains(annotation, "@") {
		return true
	}
	return false
}

func imageRefLocalName(ref string) string {
	ref = strings.TrimSpace(ref)
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i >= 0 && !strings.Contains(ref[i+1:], "/") {
		before := ref[:i]
		if strings.Contains(before, "/") {
			ref = before
		}
	}
	return ref
}

func digestFromImageRef(ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	idx := strings.LastIndex(ref, "@")
	if idx < 0 {
		return "", false
	}
	digest := ref[idx+1:]
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		return "", false
	}
	for _, c := range digest[len("sha256:"):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return digest, true
}

// TagCandidatesForReference returns ctr image tag source candidates that are
// safe to use for a desired reference. Preferred sources should come from the
// just-imported refs for the current archive so stale local aliases are not
// silently re-used across upgrades.
func TagCandidatesForReference(contentDigest string, present map[string]bool, preferredSources []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" || seen[ref] {
			return
		}
		seen[ref] = true
		out = append(out, ref)
	}

	for _, ref := range preferredSources {
		add(ref)
	}
	add(contentDigest)
	if present != nil {
		for ref := range present {
			if ref == contentDigest || strings.HasSuffix(ref, "@"+contentDigest) || strings.Contains(ref, contentDigest) {
				add(ref)
			}
		}
	}
	return out
}
