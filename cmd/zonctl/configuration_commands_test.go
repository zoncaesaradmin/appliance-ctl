package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/configarchive"
)

func TestConfigurationExportAndImportOverHTTPS(t *testing.T) {
	payload := json.RawMessage(`{"apiVersion":"configuration.zon/v1","customProfiles":[],"profileActivation":{},"dnsRecords":[],"builderCatalog":{"document":"","contentType":"application/json"},"applicationDefinitions":[],"applicationInstances":[]}`)
	var imported json.RawMessage
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer operator-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/configuration/revisions":
			if r.Method != http.MethodPost {
				http.Error(w, "method", http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "revision-1", "schemaVersion": "configuration.zon/v1", "payload": payload})
		case "/api/v1/configuration/revisions/import":
			var body struct {
				Payload json.RawMessage `json:"payload"`
				Replace bool            `json:"replace"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !body.Replace {
				http.Error(w, "replacement confirmation required", http.StatusConflict)
				return
			}
			imported = body.Payload
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	oldClient := configurationHTTPClient
	configurationHTTPClient = server.Client()
	t.Cleanup(func() { configurationHTTPClient = oldClient })

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	keyPath := filepath.Join(dir, "archive.key")
	archivePath := filepath.Join(dir, "configuration.archive")
	if err := os.WriteFile(tokenPath, []byte("operator-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := cliOptions{configurationEndpoint: server.URL, configurationTokenFile: tokenPath, configurationArchiveKeyFile: keyPath, configurationArchivePath: archivePath, replaceConfiguration: true}
	if result := runConfigurationExport(context.Background(), opts, nil, commandResult{}); result.Status != "succeeded" {
		t.Fatalf("export result = %+v", result)
	}
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(archivePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode info=%v err=%v", info, err)
	}
	if _, opened, err := configarchive.Open(data, key); err != nil || string(opened) != string(payload) {
		t.Fatalf("archive open = %s, %v", opened, err)
	}
	if result := runConfigurationImport(context.Background(), opts, nil, commandResult{}); result.Status != "succeeded" {
		t.Fatalf("import result = %+v", result)
	}
	if string(imported) != string(payload) {
		t.Fatalf("imported payload = %s", imported)
	}
}
