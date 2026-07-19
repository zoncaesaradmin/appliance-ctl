package images_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/images"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

// fakeCtr simulates `ctr` without touching a real containerd store, and
// records every import/rm invocation for ordering and rollback
// assertions.
type fakeCtr struct {
	alreadyImported []string
	failImport      map[string]bool // keyed by archive path
	failRemove      map[string]bool // keyed by image name
	nextImportAdds  [][]string
	sawImportDigests bool
	calls           []string
}

func (f *fakeCtr) Run(_ context.Context, name string, args ...string) (string, error) {
	if name != "ctr" {
		return "", fmt.Errorf("unexpected binary %q", name)
	}

	var verb, target string
	for i, a := range args {
		if a == "image" && i+1 < len(args) {
			verb = args[i+1]
			if verb == "import" {
				for _, candidate := range args[i+2:] {
					if !strings.HasPrefix(candidate, "-") {
						target = candidate
					}
				}
			}
			if verb == "rm" && i+2 < len(args) {
				target = args[i+2]
			}
			break
		}
	}

	switch verb {
	case "ls":
		return strings.Join(f.alreadyImported, "\n"), nil
	case "import":
		f.calls = append(f.calls, "import:"+target)
		if containsArg(args, "--digests") {
			f.sawImportDigests = true
		}
		if f.failImport[target] {
			return "", errors.New("simulated import failure")
		}
		if len(f.nextImportAdds) > 0 {
			for _, ref := range f.nextImportAdds[0] {
				f.addImported(ref)
			}
			f.nextImportAdds = f.nextImportAdds[1:]
		}
		return "", nil
	case "rm":
		f.calls = append(f.calls, "rm:"+target)
		if f.failRemove[target] {
			return "", errors.New("simulated rm failure")
		}
		return "", nil
	}
	return "", fmt.Errorf("unrecognized ctr invocation: %v", args)
}

func (f *fakeCtr) addImported(ref string) {
	for _, existing := range f.alreadyImported {
		if existing == ref {
			return
		}
	}
	f.alreadyImported = append(f.alreadyImported, ref)
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func writeArchive(t *testing.T, dir, name, content string) (path, digest string) {
	t.Helper()
	path = filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := verify.Digest(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, d
}

func writeCompressedArchive(t *testing.T, dir, name, content string) (path, digest string) {
	t.Helper()
	path = filepath.Join(dir, name)

	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	encoder, err := zstd.NewWriter(file)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := encoder.Write([]byte(content)); err != nil {
		_ = encoder.Close()
		_ = file.Close()
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	d, err := verify.Digest(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, d
}

func statusOfCheck(t *testing.T, checks []evidence.Check, id string) evidence.Status {
	t.Helper()
	for _, c := range checks {
		if c.ID == id {
			return c.Status
		}
	}
	t.Fatalf("no check with id %q found", id)
	return ""
}

// Digest: a tampered/incorrect archive must fail closed and never reach
// `ctr image import`.
func TestPreloadAll_DigestMismatchFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeArchive(t, dir, "app.tar", "image bytes")

	fake := &fakeCtr{}
	imp := &images.Importer{Run: fake.Run, Namespace: "k8s.io"}

	result, err := imp.PreloadAll(context.Background(), []images.Image{
		{Name: "app:v1", ArchivePath: path, ExpectedDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000", Category: images.CategoryApplication},
	})
	if err == nil {
		t.Fatal("expected digest mismatch to fail")
	}
	if got := statusOfCheck(t, result.Checks, "image-preload-app-v1"); got != evidence.StatusFail {
		t.Errorf("expected fail status, got %s", got)
	}
	for _, c := range fake.calls {
		if strings.HasPrefix(c, "import:") {
			t.Error("must never import an artifact whose digest does not match")
		}
	}
}

// Missing artifact: the manifest references an image archive that was
// never delivered in the bundle.
func TestPreloadAll_MissingArtifactFailsClosed(t *testing.T) {
	fake := &fakeCtr{}
	imp := &images.Importer{Run: fake.Run, Namespace: "k8s.io"}

	missing := filepath.Join(t.TempDir(), "never-delivered.tar")
	_, err := imp.PreloadAll(context.Background(), []images.Image{
		{Name: "argo-executor:v3", ArchivePath: missing, ExpectedDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000", Category: images.CategoryDependency},
	})
	if err == nil {
		t.Fatal("expected a missing archive to fail")
	}
	if len(fake.calls) != 0 {
		t.Errorf("expected no ctr invocations for a missing artifact, got %v", fake.calls)
	}
}

// Ordering: K3s platform images must import before dependency images,
// which must import before application images, regardless of input order.
func TestPreloadAll_Ordering(t *testing.T) {
	dir := t.TempDir()
	appPath, appDigest := writeArchive(t, dir, "app.tar", "application image")
	depPath, depDigest := writeArchive(t, dir, "dep.tar", "dependency image")
	platPath, platDigest := writeArchive(t, dir, "plat.tar", "platform image")

	fake := &fakeCtr{}
	imp := &images.Importer{Run: fake.Run, Namespace: "k8s.io"}

	// Deliberately out of order: application, dependency, platform.
	_, err := imp.PreloadAll(context.Background(), []images.Image{
		{Name: "application:v1", ArchivePath: appPath, ExpectedDigest: appDigest, Category: images.CategoryApplication},
		{Name: "dependency:v1", ArchivePath: depPath, ExpectedDigest: depDigest, Category: images.CategoryDependency},
		{Name: "platform:v1", ArchivePath: platPath, ExpectedDigest: platDigest, Category: images.CategoryK3sPlatform},
	})
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"import:" + platPath, "import:" + depPath, "import:" + appPath}
	if len(fake.calls) != len(want) {
		t.Fatalf("expected %d import calls, got %v", len(want), fake.calls)
	}
	for i, w := range want {
		if fake.calls[i] != w {
			t.Errorf("call %d: expected %q, got %q (full order: %v)", i, w, fake.calls[i], fake.calls)
		}
	}
}

// Idempotency: an image already present in the store must not be
// re-imported.
func TestPreloadAll_Idempotency(t *testing.T) {
	dir := t.TempDir()
	path, digest := writeArchive(t, dir, "app.tar", "application image")

	fake := &fakeCtr{alreadyImported: []string{"application:v1"}}
	imp := &images.Importer{Run: fake.Run, Namespace: "k8s.io"}

	result, err := imp.PreloadAll(context.Background(), []images.Image{
		{Name: "application:v1", ArchivePath: path, ExpectedDigest: digest, Category: images.CategoryApplication},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 0 {
		t.Errorf("expected no import call for an already-present image, got %v", fake.calls)
	}
	if len(result.NewlyImported) != 0 {
		t.Errorf("expected NewlyImported to be empty, got %v", result.NewlyImported)
	}
	if got := statusOfCheck(t, result.Checks, "image-preload-application-v1"); got != evidence.StatusPass {
		t.Errorf("expected pass, got %s", got)
	}
}

func TestPreloadAll_DecompressesTarZstBeforeImport(t *testing.T) {
	dir := t.TempDir()
	path, digest := writeCompressedArchive(t, dir, "k3s-airgap-images-amd64.tar.zst", "not-a-real-tar-but-good-enough-for-unit-test")

	fake := &fakeCtr{nextImportAdds: [][]string{{"k3s-airgap-images:v1"}}}
	imp := &images.Importer{Run: fake.Run, Namespace: "k8s.io"}

	result, err := imp.PreloadAll(context.Background(), []images.Image{
		{Name: "k3s-airgap-images:v1", ArchivePath: path, ExpectedDigest: digest, Category: images.CategoryK3sPlatform},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.NewlyImported) != 1 {
		t.Fatalf("expected one imported image, got %v", result.NewlyImported)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("expected one import call, got %v", fake.calls)
	}

	importedPath := strings.TrimPrefix(fake.calls[0], "import:")
	if importedPath == path {
		t.Fatalf("expected compressed archive to be decompressed to a temp tar before import, got original path %q", importedPath)
	}
	if !strings.HasSuffix(importedPath, ".tar") {
		t.Fatalf("expected decompressed import path to end with .tar, got %q", importedPath)
	}
	if _, err := os.Stat(importedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected temp import archive to be removed after import, stat err=%v", err)
	}
}

func TestPreloadAll_ImportsWithDigestsAndVerifiesRequiredReference(t *testing.T) {
	dir := t.TempDir()
	path, digest := writeArchive(t, dir, "buildah.tar", "builder image")
	imageRef := "registry.local/buildah@sha256:approved"

	fake := &fakeCtr{nextImportAdds: [][]string{{imageRef}}}
	imp := &images.Importer{Run: fake.Run, Namespace: "k8s.io"}

	result, err := imp.PreloadAll(context.Background(), []images.Image{
		{Name: imageRef, ArchivePath: path, ExpectedDigest: digest, Category: images.CategoryApplication, RequireReference: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("expected one import call, got %v", fake.calls)
	}
	if got, want := fake.calls[0], "import:"+path; got != want {
		t.Fatalf("import call = %q, want %q", got, want)
	}
	if len(result.NewlyImported) != 1 || result.NewlyImported[0] != imageRef {
		t.Fatalf("NewlyImported = %v, want %q", result.NewlyImported, imageRef)
	}
	if !fake.sawImportDigests {
		t.Fatal("expected ctr image import to include --digests for digest-pinned local resolution")
	}
}

func TestPreloadAll_MissingRequiredReferenceFailsAfterImport(t *testing.T) {
	dir := t.TempDir()
	path, digest := writeArchive(t, dir, "buildah.tar", "builder image")
	imageRef := "registry.local/buildah@sha256:approved"

	fake := &fakeCtr{nextImportAdds: [][]string{{"registry.local/other@sha256:approved"}}}
	imp := &images.Importer{Run: fake.Run, Namespace: "k8s.io"}

	result, err := imp.PreloadAll(context.Background(), []images.Image{
		{Name: imageRef, ArchivePath: path, ExpectedDigest: digest, Category: images.CategoryApplication, RequireReference: true},
	})
	if err == nil {
		t.Fatal("expected missing required reference to fail")
	}
	if !strings.Contains(err.Error(), "expected image reference not present after import") {
		t.Fatalf("error = %v, want expected-reference failure", err)
	}
	if got := statusOfCheck(t, result.Checks, "image-preload-registry-local-buildah-sha256-approved"); got != evidence.StatusFail {
		t.Errorf("expected fail status, got %s", got)
	}
}

// Rollback: images newly imported this run can be removed again, and a
// partial removal failure is reported rather than silently swallowed.
func TestImporter_Rollback(t *testing.T) {
	dir := t.TempDir()
	path1, digest1 := writeArchive(t, dir, "one.tar", "one")
	path2, digest2 := writeArchive(t, dir, "two.tar", "two")

	fake := &fakeCtr{nextImportAdds: [][]string{{"one:v1"}, {"two:v1"}}}
	imp := &images.Importer{Run: fake.Run, Namespace: "k8s.io"}

	result, err := imp.PreloadAll(context.Background(), []images.Image{
		{Name: "one:v1", ArchivePath: path1, ExpectedDigest: digest1, Category: images.CategoryApplication},
		{Name: "two:v1", ArchivePath: path2, ExpectedDigest: digest2, Category: images.CategoryApplication},
	})
	if err != nil {
		t.Fatal(err)
	}

	fake.failRemove = map[string]bool{"two:v1": true}
	if err := imp.Rollback(context.Background(), result.NewlyImported); err == nil {
		t.Error("expected rollback to report the simulated removal failure")
	}
	if !strings.Contains(strings.Join(fake.calls, ","), "rm:one:v1") || !strings.Contains(strings.Join(fake.calls, ","), "rm:two:v1") {
		t.Errorf("expected rollback to attempt removing both images, got %v", fake.calls)
	}
}

// Offline regression: preloading and rolling back must never touch the
// network. The fake runner already avoids invoking real ctr, but this
// proves this package's own Go code (digest verification, ordering, list
// parsing) never resolves a hostname either.
func TestPreloadAll_RequiresNoNetworkAccess(t *testing.T) {
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("network access is not permitted in this test")
		},
	}
	t.Cleanup(func() { net.DefaultResolver = original })

	dir := t.TempDir()
	path, digest := writeArchive(t, dir, "app.tar", "application image")

	fake := &fakeCtr{}
	imp := &images.Importer{Run: fake.Run, Namespace: "k8s.io"}

	result, err := imp.PreloadAll(context.Background(), []images.Image{
		{Name: "application:v1", ArchivePath: path, ExpectedDigest: digest, Category: images.CategoryApplication},
	})
	if err != nil {
		t.Fatalf("PreloadAll should succeed offline: %v", err)
	}
	if err := imp.Rollback(context.Background(), result.NewlyImported); err != nil {
		t.Fatalf("Rollback should succeed offline: %v", err)
	}
}
