package manifest_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/manifest"
)

// fixtureDirs maps each schema kind to its fixtures directory, relative to
// the repository root. Every JSON file under valid/ must pass validation;
// every JSON file under invalid/ must fail it.
var fixtureDirs = map[manifest.Kind]string{
	manifest.KindReleaseInput:    "release-input",
	manifest.KindReleaseManifest: "release-manifest",
	manifest.KindInstalledState:  "installed-state",
	manifest.KindEvidence:        "evidence",
	manifest.KindCommandResult:   "command",
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, "..", "..")
}

func TestCompileDoesNotRequireCurrentWorkingDirectory(t *testing.T) {
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalWD); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})

	dir := filepath.Join(t.TempDir(), "deleted-cwd")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}

	if _, err := manifest.Compile(manifest.KindCommandResult); err != nil {
		t.Fatalf("compile schema with deleted cwd: %v", err)
	}
}

func TestFixtures(t *testing.T) {
	root := repoRoot(t)

	for kind, dir := range fixtureDirs {
		kind, dir := kind, dir
		t.Run(string(kind), func(t *testing.T) {
			base := filepath.Join(root, "tests", "fixtures", dir)

			runCases(t, kind, filepath.Join(base, "valid"), true)
			runCases(t, kind, filepath.Join(base, "invalid"), false)
		})
	}
}

func runCases(t *testing.T, kind manifest.Kind, dir string, wantValid bool) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	if len(entries) == 0 {
		t.Fatalf("no fixtures found in %s", dir)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		entry := entry
		t.Run(entry.Name(), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}

			err = manifest.Validate(kind, data)
			if wantValid && err != nil {
				t.Errorf("expected valid fixture to pass, got error: %v", err)
			}
			if !wantValid && err == nil {
				t.Errorf("expected invalid fixture to fail validation, but it passed")
			}
		})
	}
}
