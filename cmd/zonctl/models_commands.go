package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdirs"
	"github.com/zoncaesaradmin/appliance-ctl/internal/modelpack"
	"github.com/zoncaesaradmin/appliance-ctl/internal/verify"
)

func runModelsImport(ctx context.Context, opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	_ = ctx
	packDir := strings.TrimSpace(opts.bundleDir)
	if packDir == "" {
		return finish(result, "failed", 2, "models-import: --bundle-dir must point at an extracted model pack directory", nil)
	}
	modelsDir := hostdirs.InferenceModelsDir
	if custom := strings.TrimSpace(os.Getenv("ZONCTL_INFERENCE_MODELS_DIR")); custom != "" {
		modelsDir = custom
	}

	var pub *verify.PublicKey
	if keyPath := strings.TrimSpace(opts.publicKey); keyPath != "" {
		loaded, err := verify.LoadPublicKey("release-signing-key", keyPath)
		if err != nil {
			return finish(result, "failed", 1, fmt.Sprintf("models-import: load public key: %v", err), nil)
		}
		pub = &loaded
	}

	pack, err := modelpack.Load(packDir, pub)
	if err != nil {
		return finish(result, "failed", 1, fmt.Sprintf("models-import: %v", err), nil)
	}
	if err := hostdirs.EnsureOwnedDir(modelsDir, hostdirs.InferenceDirOwnerUID, hostdirs.ApplianceSharedFSGID, 0o2770, os.Chown); err != nil {
		return finish(result, "failed", 1, fmt.Sprintf("models-import: prepare models directory: %v", err), nil)
	}
	dest, err := pack.Import(modelsDir)
	if err != nil {
		return finish(result, "failed", 1, fmt.Sprintf("models-import: %v", err), nil)
	}
	logger.Info("imported model pack",
		"modelId", pack.Manifest.ModelID,
		"runtime", pack.Manifest.Runtime,
		"destination", dest,
		"minRAMGB", pack.Manifest.MinRAMGB,
	)

	payload, _ := json.Marshal(map[string]any{
		"modelId":     pack.Manifest.ModelID,
		"runtime":     pack.Manifest.Runtime,
		"destination": dest,
		"minRAMGB":    pack.Manifest.MinRAMGB,
		"checks": []evidence.Check{{
			ID: "modelpack-imported", Category: "inference", Status: evidence.StatusPass,
			Message:   fmt.Sprintf("imported %s into %s", pack.Manifest.ModelID, dest),
			Timestamp: time.Now().UTC(), Idempotent: true, SecretsRedacted: true,
		}},
	})
	return finish(result, "succeeded", 0, fmt.Sprintf("imported model %s into %s", pack.Manifest.ModelID, filepath.Clean(dest)), payload)
}
