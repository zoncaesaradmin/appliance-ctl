package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/zoncaesaradmin/appliance-ctl/internal/releasebundle"
)

func runAssembleBundle(opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	if opts.configPath == "" {
		return finish(result, "failed", 2, "assemble-bundle: --config is required", nil)
	}

	cfg, err := releasebundle.LoadConfig(opts.configPath)
	if err != nil {
		logger.Error("failed to load bundle assembly config", "error", err, "path", opts.configPath)
		return finish(result, "failed", 1, err.Error(), nil)
	}

	assembled, err := releasebundle.Assemble(context.Background(), cfg)
	if err != nil {
		logger.Error("bundle assembly failed", "error", err, "bundleDir", cfg.BundleDir)
		return finish(result, "failed", 1, err.Error(), nil)
	}

	data, _ := json.Marshal(map[string]any{
		"bundleDir":     assembled.BundleDir,
		"bundleVersion": assembled.BundleVersion,
		"releaseId":     assembled.ReleaseID,
		"manifestPath":  assembled.ManifestPath,
		"signaturePath": assembled.SignaturePath,
		"publicKeyPath": assembled.PublicKeyPath,
		"entryCount":    assembled.EntryCount,
	})
	return finish(result, "succeeded", 0, fmt.Sprintf("assembled bundle %s", assembled.BundleDir), data)
}

func runVerifyBundle(opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	if opts.bundleDir == "" || opts.publicKey == "" {
		return finish(result, "failed", 2, "verify-bundle: --bundle-dir and --public-key are required", nil)
	}

	b, err := releasebundle.VerifyBundle(opts.bundleDir, opts.publicKey)
	if err != nil {
		logger.Error("bundle verification failed", "error", err, "bundleDir", opts.bundleDir, "publicKey", opts.publicKey)
		return finish(result, "failed", 1, err.Error(), nil)
	}

	data, _ := json.Marshal(map[string]any{
		"bundleDir":     opts.bundleDir,
		"bundleVersion": b.BundleVersion,
		"releaseId":     b.ReleaseID,
		"k3sVersion":    b.Compatibility.K3sVersion,
		"chartVersion":  b.Compatibility.ChartVersion,
		"argoVersion":   b.Compatibility.ArgoVersion,
	})
	return finish(result, "succeeded", 0, fmt.Sprintf("verified bundle %s", opts.bundleDir), data)
}
