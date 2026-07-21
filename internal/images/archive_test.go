package images_test

import (
	"archive/tar"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/images"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

func writeOCIArchive(t *testing.T, dir, name, annotatedRef, contentDigest string) (string, string) {
	t.Helper()
	index := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []map[string]any{
			{
				"mediaType": "application/vnd.oci.image.manifest.v1+json",
				"digest":    contentDigest,
				"size":      2,
				"annotations": map[string]string{
					"org.opencontainers.image.ref.name": annotatedRef,
				},
			},
		},
	}
	payload, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	hdr := &tar.Header{Name: "index.json", Mode: 0o644, Size: int64(len(payload))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	digest, err := verify.Digest(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, digest
}

func TestValidateOCIArchiveReference_Mismatch(t *testing.T) {
	dir := t.TempDir()
	contentDigest := "sha256:5e1543841d987081a1e0e37305039b2bb9908592a4cddad95b4c4c49d07653a3"
	annotatedRef := "registry.local/workspace-provisioner@sha256:77418e6e7c7f434c4a98eaff04ef16840cf03649c881c03948e3e213923e3136"
	path, _ := writeOCIArchive(t, dir, "workspace-provisioner.tar", annotatedRef, contentDigest)

	err := images.ValidateOCIArchiveReference(path, annotatedRef)
	if err == nil {
		t.Fatal("expected mismatch to fail")
	}
	if !strings.Contains(err.Error(), "does not match expected reference digest") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateOCIArchiveReference_AcceptsBundledTagAnnotation(t *testing.T) {
	dir := t.TempDir()
	digest := "sha256:5e1543841d987081a1e0e37305039b2bb9908592a4cddad95b4c4c49d07653a3"
	ref := "registry.local/workspace-provisioner@" + digest
	path, _ := writeOCIArchive(t, dir, "workspace-provisioner.tar", "registry.local/workspace-provisioner:bundled", digest)

	if err := images.ValidateOCIArchiveReference(path, ref); err != nil {
		t.Fatal(err)
	}
}

func TestValidateOCIArchiveReference_AcceptsAutomationDevBundledTag(t *testing.T) {
	dir := t.TempDir()
	digest := "sha256:5ccdfda08e940614d030e377b75f048a55e3f61cbb0234294ad333f27afe222c"
	ref := "registry.local/automation-dev@" + digest
	path, _ := writeOCIArchive(t, dir, "automation-dev.tar", "registry.local/automation-dev:bundled", digest)

	if err := images.ValidateOCIArchiveReference(path, ref); err != nil {
		t.Fatal(err)
	}
}

func TestValidateOCIArchiveReference_NonOCISkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stub.tar")
	if err := os.WriteFile(path, []byte("not an oci archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	ref := "registry.local/buildah@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := images.ValidateOCIArchiveReference(path, ref); err != nil {
		t.Fatal(err)
	}
}

func TestPreloadAll_RejectsMismatchedOCIArchiveReference(t *testing.T) {
	dir := t.TempDir()
	contentDigest := "sha256:5e1543841d987081a1e0e37305039b2bb9908592a4cddad95b4c4c49d07653a3"
	annotatedRef := "registry.local/workspace-provisioner@sha256:77418e6e7c7f434c4a98eaff04ef16840cf03649c881c03948e3e213923e3136"
	path, digest := writeOCIArchive(t, dir, "workspace-provisioner.tar", annotatedRef, contentDigest)

	fake := &fakeCtr{}
	imp := &images.Importer{Run: fake.Run, Namespace: "k8s.io"}
	result, err := imp.PreloadAll(context.Background(), []images.Image{
		{Name: annotatedRef, ArchivePath: path, ExpectedDigest: digest, Category: images.CategoryApplication, RequireReference: true},
	})
	if err == nil {
		t.Fatal("expected mismatched OCI archive to fail preload")
	}
	if !strings.Contains(err.Error(), "does not match expected reference digest") {
		t.Fatalf("error = %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected no import calls, got %v", fake.calls)
	}
	if got := statusOfCheck(t, result.Checks, "image-preload-registry-local-workspace-provisioner-sha256-77418e6e7c7f434c4a98eaff04ef16840cf03649c881c03948e3e213923e3136"); got != evidence.StatusFail {
		t.Errorf("expected fail status, got %s", got)
	}
}

func TestPreloadAll_TagsDigestPinnedNameFromBundledAnnotation(t *testing.T) {
	dir := t.TempDir()
	digest := "sha256:5e1543841d987081a1e0e37305039b2bb9908592a4cddad95b4c4c49d07653a3"
	imageRef := "registry.local/workspace-provisioner@" + digest
	path, fileDigest := writeOCIArchive(t, dir, "workspace-provisioner.tar", "registry.local/workspace-provisioner:bundled", digest)

	fake := &fakeCtr{nextImportAdds: [][]string{{"registry.local/workspace-provisioner:bundled"}}}
	imp := &images.Importer{Run: fake.Run, Namespace: "k8s.io"}
	result, err := imp.PreloadAll(context.Background(), []images.Image{
		{Name: imageRef, ArchivePath: path, ExpectedDigest: fileDigest, Category: images.CategoryApplication, RequireReference: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(fake.calls, ",")
	if !strings.Contains(joined, "tag:registry.local/workspace-provisioner:bundled>"+imageRef) {
		t.Fatalf("expected tag from :bundled to digest pin, got %v", fake.calls)
	}
	found := false
	for _, ref := range result.NewlyImported {
		if ref == imageRef {
			found = true
		}
	}
	if !found {
		t.Fatalf("NewlyImported = %v, want %q", result.NewlyImported, imageRef)
	}
}
