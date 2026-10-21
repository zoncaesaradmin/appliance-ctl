package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/configarchive"
)

var configurationHTTPClient = &http.Client{Timeout: 30 * time.Second}

type configurationRevisionResponse struct {
	ID            string          `json:"id"`
	SchemaVersion string          `json:"schemaVersion"`
	Payload       json.RawMessage `json:"payload"`
}

func runConfigurationExport(ctx context.Context, opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	endpoint, token, key, err := configurationCommandInputs(opts)
	if err != nil {
		return finish(result, "failed", 1, "configuration-export: "+err.Error(), nil)
	}
	if opts.configurationArchivePath == "" {
		return finish(result, "failed", 1, "configuration-export: --configuration-archive is required", nil)
	}
	revision, err := captureConfiguration(ctx, endpoint, token)
	if err != nil {
		if logger != nil {
			logger.Error("configuration export capture failed", "error", err)
		}
		return finish(result, "failed", 1, "configuration-export: "+err.Error(), nil)
	}
	archive, manifest, err := configarchive.Seal(revision.ID, revision.SchemaVersion, revision.Payload, key)
	if err != nil {
		return finish(result, "failed", 1, "configuration-export: "+err.Error(), nil)
	}
	if opts.dryRun {
		return finish(result, "succeeded", 0, "configuration archive validated (dry run)", configurationData(manifest.ArchiveID, manifest.RevisionID, ""))
	}
	if err := writeProtectedArchive(opts.configurationArchivePath, archive); err != nil {
		return finish(result, "failed", 1, "configuration-export: "+err.Error(), nil)
	}
	return finish(result, "succeeded", 0, "configuration archive exported", configurationData(manifest.ArchiveID, manifest.RevisionID, opts.configurationArchivePath))
}

func runConfigurationImport(ctx context.Context, opts cliOptions, logger *slog.Logger, result commandResult) commandResult {
	endpoint, token, key, err := configurationCommandInputs(opts)
	if err != nil {
		return finish(result, "failed", 1, "configuration-import: "+err.Error(), nil)
	}
	if opts.configurationArchivePath == "" {
		return finish(result, "failed", 1, "configuration-import: --configuration-archive is required", nil)
	}
	data, err := os.ReadFile(opts.configurationArchivePath)
	if err != nil {
		return finish(result, "failed", 1, "configuration-import: read archive: "+err.Error(), nil)
	}
	manifest, payload, err := configarchive.Open(data, key)
	if err != nil {
		return finish(result, "failed", 1, "configuration-import: "+err.Error(), nil)
	}
	if opts.dryRun {
		return finish(result, "succeeded", 0, "configuration archive verified (dry run)", configurationData(manifest.ArchiveID, manifest.RevisionID, ""))
	}
	if err := importConfiguration(ctx, endpoint, token, payload); err != nil {
		if logger != nil {
			logger.Error("configuration import failed", "error", err)
		}
		return finish(result, "failed", 1, "configuration-import: "+err.Error(), nil)
	}
	return finish(result, "succeeded", 0, "configuration archive imported; reconciliation is pending", configurationData(manifest.ArchiveID, manifest.RevisionID, ""))
}

func configurationData(archiveID, revisionID, path string) json.RawMessage {
	data, _ := json.Marshal(map[string]string{"archiveId": archiveID, "revisionId": revisionID, "path": path})
	return data
}

func configurationCommandInputs(opts cliOptions) (string, string, []byte, error) {
	if opts.configurationEndpoint == "" || opts.configurationTokenFile == "" || opts.configurationArchiveKeyFile == "" {
		return "", "", nil, fmt.Errorf("--configuration-endpoint, --configuration-token-file, and --configuration-archive-key-file are required")
	}
	u, err := url.Parse(opts.configurationEndpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", "", nil, fmt.Errorf("--configuration-endpoint must be an absolute HTTPS URL")
	}
	tokenData, err := os.ReadFile(opts.configurationTokenFile)
	if err != nil || strings.TrimSpace(string(tokenData)) == "" {
		return "", "", nil, fmt.Errorf("read non-empty configuration token file")
	}
	key, err := readConfigurationArchiveKey(opts.configurationArchiveKeyFile)
	if err != nil {
		return "", "", nil, err
	}
	return strings.TrimRight(opts.configurationEndpoint, "/"), strings.TrimSpace(string(tokenData)), key, nil
}

func readConfigurationArchiveKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read configuration archive key file: %w", err)
	}
	data = bytes.TrimSpace(data)
	if len(data) == 32 {
		return append([]byte(nil), data...), nil
	}
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("configuration archive key file must contain exactly 32 raw bytes or base64 for 32 bytes")
	}
	return decoded, nil
}

func captureConfiguration(ctx context.Context, endpoint, token string) (configurationRevisionResponse, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/api/v1/configuration/revisions", strings.NewReader("{}"))
	if err != nil {
		return configurationRevisionResponse{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := configurationHTTPClient.Do(request)
	if err != nil {
		return configurationRevisionResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return configurationRevisionResponse{}, apiFailure(response)
	}
	var revision configurationRevisionResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&revision); err != nil || revision.ID == "" || revision.SchemaVersion == "" || !json.Valid(revision.Payload) {
		return configurationRevisionResponse{}, fmt.Errorf("invalid configuration capture response")
	}
	return revision, nil
}

func importConfiguration(ctx context.Context, endpoint, token string, payload []byte) error {
	body, err := json.Marshal(map[string]json.RawMessage{"payload": payload})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/api/v1/configuration/revisions/import", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := configurationHTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return apiFailure(response)
	}
	return nil
}

func apiFailure(response *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	return fmt.Errorf("control-plane API returned %s: %s", response.Status, strings.TrimSpace(string(data)))
}

func writeProtectedArchive(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".configuration-archive-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}
