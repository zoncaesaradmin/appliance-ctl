package images

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

// Importer preloads OCI image archives into a containerd image store via
// `ctr`, the tool K3s itself embeds.
type Importer struct {
	Run       cli.Runner
	Namespace string // containerd namespace; "k8s.io" for K3s
}

// NewImporter returns an Importer using the real `ctr` binary. Pass a
// fake cli.Runner in tests instead of constructing this directly.
func NewImporter() *Importer {
	return &Importer{Run: cli.Exec, Namespace: "k8s.io"}
}

// Imported lists image references already present in the store, so
// PreloadAll can skip them (idempotency).
func (imp *Importer) Imported(ctx context.Context) (map[string]bool, error) {
	out, err := imp.Run(ctx, "ctr", "-n", imp.Namespace, "image", "ls", "-q")
	if err != nil {
		return nil, fmt.Errorf("images: list imported images: %w", err)
	}

	set := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			set[line] = true
		}
	}
	return set, nil
}

// PreloadResult is the outcome of a PreloadAll call: the evidence checks
// (for the support bundle/evidence report) and the names of images newly
// imported this run, which Rollback needs to undo only what this run
// actually did.
type PreloadResult struct {
	Checks        []evidence.Check
	NewlyImported []string
}

// PreloadAll verifies and imports every image, in Category order,
// skipping any already present. It never touches the network: digest
// verification and `ctr image import` both operate purely on local
// files. It fails closed and returns the full check set (including
// failures) even on error, so the caller can still persist an evidence
// report and decide whether to roll back NewlyImported.
func (imp *Importer) PreloadAll(ctx context.Context, images []Image) (PreloadResult, error) {
	already, err := imp.Imported(ctx)
	if err != nil {
		return PreloadResult{}, err
	}

	var result PreloadResult
	var failures []error

	for _, img := range Ordered(images) {
		check := evidence.Check{
			ID:              "image-preload-" + img.Name,
			Category:        "dependency",
			Timestamp:       time.Now().UTC(),
			Idempotent:      true,
			SecretsRedacted: true,
		}

		if err := verify.VerifyDigest(img.ArchivePath, img.ExpectedDigest); err != nil {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			failures = append(failures, fmt.Errorf("%s: %w", img.Name, err))
			result.Checks = append(result.Checks, check)
			continue
		}

		if already[img.Name] {
			check.Status = evidence.StatusPass
			check.Message = fmt.Sprintf("%s already imported (idempotent no-op)", img.Name)
			result.Checks = append(result.Checks, check)
			continue
		}

		if _, err := imp.Run(ctx, "ctr", "-n", imp.Namespace, "image", "import", img.ArchivePath); err != nil {
			check.Status = evidence.StatusFail
			check.Message = fmt.Sprintf("import %s: %v", img.Name, err)
			failures = append(failures, fmt.Errorf("%s: %w", img.Name, err))
			result.Checks = append(result.Checks, check)
			continue
		}

		check.Status = evidence.StatusPass
		check.Message = fmt.Sprintf("%s imported from %s", img.Name, img.ArchivePath)
		result.Checks = append(result.Checks, check)
		result.NewlyImported = append(result.NewlyImported, img.Name)
	}

	if len(failures) > 0 {
		return result, fmt.Errorf("images: %d image(s) failed to preload: %w", len(failures), errors.Join(failures...))
	}
	return result, nil
}

// Rollback removes each named image from the store. It is intended for
// images this run newly imported (PreloadResult.NewlyImported), never
// ones that were already present before this run started, so a failed
// install leaves the store no more populated than it was beforehand. It
// is best-effort: it attempts every name and aggregates failures rather
// than stopping at the first one.
func (imp *Importer) Rollback(ctx context.Context, names []string) error {
	var failures []error
	for _, name := range names {
		if _, err := imp.Run(ctx, "ctr", "-n", imp.Namespace, "image", "rm", name); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("images: %d image(s) failed to roll back: %w", len(failures), errors.Join(failures...))
	}
	return nil
}
