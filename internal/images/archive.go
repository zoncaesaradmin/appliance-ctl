package images

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// ValidateOCIArchiveReference checks that an OCI-layout archive's annotated
// image reference matches expectedRef and that the digest embedded in that
// reference equals the archived manifest digest. Non-OCI archives (plain
// docker-save stubs, test fixtures) are skipped. Tag-only expectedRef values
// are skipped: RequireReference still enforces name presence after import, but
// content-digest equality only applies to digest-pinned refs.
//
// This catches a packaging failure mode where skopeo labels an archive with a
// multi-arch index digest while materializing a single-platform manifest.
// After ctr import, kubelet then fails with CreateContainerError / image not found.
func ValidateOCIArchiveReference(archivePath, expectedRef string) error {
	expectedRef = strings.TrimSpace(expectedRef)
	if expectedRef == "" {
		return fmt.Errorf("images: expected image reference is empty")
	}
	expectedDigest, ok := digestFromImageRef(expectedRef)
	if !ok {
		return nil
	}

	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("images: open archive %s: %w", archivePath, err)
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
			// Not a readable tar — treat as non-OCI layout.
			return nil
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if name == "index.json" {
			indexRaw, err = io.ReadAll(io.LimitReader(tr, 1<<20))
			if err != nil {
				return fmt.Errorf("images: read index.json from %s: %w", archivePath, err)
			}
			break
		}
	}
	if indexRaw == nil {
		return nil
	}

	var index struct {
		Manifests []struct {
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(indexRaw, &index); err != nil {
		return fmt.Errorf("images: parse index.json from %s: %w", archivePath, err)
	}
	if len(index.Manifests) == 0 {
		return fmt.Errorf("images: archive %s has no manifests in index.json", archivePath)
	}

	chosen := index.Manifests[0]
	for _, m := range index.Manifests {
		if m.Annotations["org.opencontainers.image.ref.name"] == expectedRef {
			chosen = m
			break
		}
	}
	contentDigest := strings.TrimSpace(chosen.Digest)
	if contentDigest != expectedDigest {
		return fmt.Errorf(
			"images: archive %s manifest digest %s does not match expected reference digest %s (%s); rebuild/export the archive by copying the digest-pinned platform image",
			archivePath, contentDigest, expectedDigest, expectedRef,
		)
	}
	ann := chosen.Annotations["org.opencontainers.image.ref.name"]
	if ann != "" && ann != expectedRef {
		return fmt.Errorf(
			"images: archive %s annotation ref %q does not match expected reference %q",
			archivePath, ann, expectedRef,
		)
	}
	if annDigest, ok := digestFromImageRef(ann); ok && annDigest != contentDigest {
		return fmt.Errorf(
			"images: archive %s annotation digest %s does not match archived manifest digest %s",
			archivePath, annDigest, contentDigest,
		)
	}
	return nil
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
