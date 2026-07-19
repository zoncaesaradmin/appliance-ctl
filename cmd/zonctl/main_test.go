package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
	"github.com/zoncaesaradmin/appliance-ctl/internal/support"
)

func captureStdout(t *testing.T, fn func() int) (string, int) {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	var exitCode int
	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		io.Copy(&buf, r)
		close(done)
	}()

	exitCode = fn()

	w.Close()
	os.Stdout = old
	<-done

	return buf.String(), exitCode
}

func TestRun_UnknownCommand(t *testing.T) {
	_, code := captureStdout(t, func() int { return run([]string{"frobnicate"}) })
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestRun_InvalidOutputFlag(t *testing.T) {
	_, code := captureStdout(t, func() int {
		return run([]string{"status", "--output", "xml", "--state-dir", t.TempDir()})
	})
	if code != 2 {
		t.Errorf("expected exit code 2 for invalid --output, got %d", code)
	}
}

// Destructive confirmation: uninstall must refuse without --confirm,
// before ever touching K3s.
func TestRun_UninstallRequiresConfirmation(t *testing.T) {
	out, code := captureStdout(t, func() int {
		return run([]string{"uninstall", "--output", "json", "--state-dir", t.TempDir()})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(out, "--confirm") {
		t.Errorf("expected a clear missing-confirmation error, got: %s", out)
	}
}

// Destructive confirmation: factory-reset must refuse at each of its
// three independent gates (token, acknowledgment, backup/override),
// never falling through to the actual teardown.
func TestRun_FactoryResetRequiresFullConfirmation(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no confirm", nil, "--confirm"},
		{"no acknowledgment", []string{"--confirm", "yes"}, "--acknowledge-data-loss"},
		{"no backup or override", []string{"--confirm", "yes", "--acknowledge-data-loss"}, "--backup-id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"factory-reset", "--output", "json", "--state-dir", t.TempDir()}, tc.args...)
			out, code := captureStdout(t, func() int { return run(args) })
			if code != 1 {
				t.Errorf("expected exit code 1, got %d", code)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("expected error mentioning %q, got: %s", tc.want, out)
			}
		})
	}
}

func TestRun_FactoryResetAcceptsWipeWorkspacesFlag(t *testing.T) {
	out, code := captureStdout(t, func() int {
		return run([]string{"factory-reset", "--wipe-workspaces", "--output", "json", "--state-dir", t.TempDir()})
	})
	if code != 1 {
		t.Errorf("expected confirmation failure exit code 1, got %d", code)
	}
	if !strings.Contains(out, "--confirm") {
		t.Errorf("expected --wipe-workspaces to parse and reach confirmation validation, got: %s", out)
	}
}

func TestRun_MutatingCommandWritesJournal(t *testing.T) {
	stateDir := t.TempDir()

	// No --bundle-dir: install's real body fails fast with a clear error,
	// but the journal must still record the attempted transaction.
	_, code := captureStdout(t, func() int {
		return run([]string{"install", "--state-dir", stateDir})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	journalPath := filepath.Join(stateDir, "transaction.json")
	if _, err := os.Stat(journalPath); err != nil {
		t.Fatalf("expected a transaction journal to be written, stat error: %v", err)
	}
}

// The signed bundle is the only supported v1 install source.
func TestRun_InstallRequiresBundleDir(t *testing.T) {
	out, code := captureStdout(t, func() int {
		return run([]string{"install", "--output", "json", "--state-dir", t.TempDir()})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(out, "--bundle-dir is required") {
		t.Errorf("expected a clear missing --bundle-dir error, got: %s", out)
	}
}

// With --bundle-dir present, install should advance to bundle loading
// rather than failing the upfront source-selection gate.
func TestRun_InstallBundleDirAdvancesToBundleLoad(t *testing.T) {
	out, code := captureStdout(t, func() int {
		return run([]string{"install", "--output", "json", "--state-dir", t.TempDir(), "--bundle-dir", filepath.Join(t.TempDir(), "missing-bundle")})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if strings.Contains(out, "--bundle-dir is required") {
		t.Errorf("expected --bundle-dir to avoid the missing-bundle-dir error entirely, got: %s", out)
	}
}

func TestRun_DryRunDoesNotWriteJournal(t *testing.T) {
	stateDir := t.TempDir()

	_, code := captureStdout(t, func() int {
		return run([]string{"install", "--dry-run", "--state-dir", stateDir})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	journalPath := filepath.Join(stateDir, "transaction.json")
	if _, err := os.Stat(journalPath); !os.IsNotExist(err) {
		t.Errorf("expected --dry-run to leave no journal file, stat err=%v", err)
	}
}

// The real preflight body now runs for real: it must produce a
// schema-shaped result with the two fields the command-result schema
// requires for preflight (overallStatus, evidenceReportId), whatever the
// actual verdict on this machine happens to be.
func TestRun_PreflightProducesSchemaShapedResult(t *testing.T) {
	stateDir := t.TempDir()

	out, _ := captureStdout(t, func() int {
		return run([]string{"preflight", "--output", "json", "--state-dir", stateDir})
	})
	if !strings.Contains(out, `"overallStatus"`) || !strings.Contains(out, `"evidenceReportId"`) {
		t.Errorf("expected preflight result data to include overallStatus and evidenceReportId, got: %s", out)
	}
}

// Dependency failure: status must report an unhealthy k3s dependency
// (never running on this dev machine) with the correct schema shape and
// a non-zero exit code, without treating the command itself as failed.
func TestRun_StatusReportsK3sDependencyFailure(t *testing.T) {
	stateDir := t.TempDir()

	out, code := captureStdout(t, func() int {
		return run([]string{"status", "--output", "json", "--state-dir", stateDir})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 reflecting the unhealthy dependency, got %d", code)
	}

	var result struct {
		Status string `json:"status"`
		Data   struct {
			K3sHealthy      bool `json:"k3sHealthy"`
			ComponentHealth []struct {
				Name    string `json:"name"`
				Healthy bool   `json:"healthy"`
				Detail  string `json:"detail"`
			} `json:"componentHealth"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("expected valid JSON, got: %s (%v)", out, err)
	}
	if result.Status != "succeeded" {
		t.Errorf("expected the status command itself to succeed even when it reports bad health, got %q", result.Status)
	}
	if result.Data.K3sHealthy {
		t.Error("expected k3sHealthy=false since k3s is never running on this dev machine")
	}
	if len(result.Data.ComponentHealth) != 1 || result.Data.ComponentHealth[0].Detail == "" {
		t.Errorf("expected a componentHealth entry with a failure detail, got %+v", result.Data.ComponentHealth)
	}
}

// Dependency failure: verify must report the missing installed-state
// dependency, again as a successful command reporting a bad verdict.
func TestRun_VerifyReportsMissingInstalledState(t *testing.T) {
	out, code := captureStdout(t, func() int {
		return run([]string{"verify", "--output", "json", "--state-dir", t.TempDir()})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(out, `"manifestValid":false`) {
		t.Errorf("expected manifestValid=false when nothing is installed, got: %s", out)
	}
}

// The support bundle must actually collect the real installed-state
// content when present, not just a diagnostics summary.
func TestRun_SupportBundleCollectsInstalledState(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Now().UTC()
	installed := &state.InstalledState{
		SchemaVersion:       1,
		ApplianceInstanceID: "test-instance",
		InstalledVersion:    "2.4.0",
		InstalledReleaseID:  "01J8QK3F9G7XA6P0V6ZC9N6R4T",
		Components:          state.Components{K3sVersion: "v1.30.4+k3s1", ChartVersion: "2.4.0"},
		K3sOwnership:        state.K3sOwnership{Owned: true, OwnerApplianceVersion: "2.4.0"},
		LastOperation: state.Operation{
			Type: "install", Status: "completed", TransactionID: "txn-test",
			StartedAt: now, CompletedAt: &now,
		},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := state.Save(filepath.Join(stateDir, "installed-state.json"), installed); err != nil {
		t.Fatal(err)
	}

	out, code := captureStdout(t, func() int {
		return run([]string{"support-bundle", "--output", "json", "--state-dir", stateDir})
	})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d: %s", code, out)
	}

	var result struct {
		Data struct {
			BundlePath string `json:"bundlePath"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("expected valid JSON, got: %s (%v)", out, err)
	}

	files, err := support.Extract(result.Data.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["installed-state.json"]; !ok {
		t.Errorf("expected installed-state.json in the support bundle, got entries: %v", keysOf(files))
	}
	if !strings.Contains(string(files["installed-state.json"]), "2.4.0") {
		t.Error("expected the collected installed-state.json to contain the real installed version")
	}
}

func keysOf(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TestRun_BackupRequiresInstalledState(t *testing.T) {
	out, code := captureStdout(t, func() int {
		return run([]string{"backup", "--output", "json", "--state-dir", t.TempDir()})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(out, "nothing is installed") {
		t.Errorf("expected a clear not-installed error, got: %s", out)
	}
}

func TestRun_UpgradeRequiresBundleDir(t *testing.T) {
	out, code := captureStdout(t, func() int {
		return run([]string{"upgrade", "--output", "json", "--state-dir", t.TempDir()})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(out, "--bundle-dir is required") {
		t.Errorf("expected a clear missing --bundle-dir error, got: %s", out)
	}
}

// With --bundle-dir present, upgrade should advance to bundle loading.
func TestRun_UpgradeBundleDirAdvancesToBundleLoad(t *testing.T) {
	out, code := captureStdout(t, func() int {
		return run([]string{"upgrade", "--output", "json", "--state-dir", t.TempDir(), "--bundle-dir", filepath.Join(t.TempDir(), "missing-bundle")})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if strings.Contains(out, "--bundle-dir is required") {
		t.Errorf("expected --bundle-dir to avoid the missing-bundle-dir error entirely, got: %s", out)
	}
}

func TestRun_RestoreRequiresBackupID(t *testing.T) {
	out, code := captureStdout(t, func() int {
		return run([]string{"restore", "--output", "json", "--state-dir", t.TempDir()})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(out, "--backup-id is required") {
		t.Errorf("expected a clear missing --backup-id error, got: %s", out)
	}
}

// Failure injection at the CLI layer: an interrupted prior operation must
// block a new mutating command, except repair.
func TestRun_InterruptedOperationBlocksNewCommandExceptRepair(t *testing.T) {
	stateDir := t.TempDir()
	journalPath := filepath.Join(stateDir, "transaction.json")
	interrupted := `{"transactionId":"txn-crashed","type":"install","status":"in-progress","startedAt":"2026-07-03T20:00:00Z"}`
	if err := os.WriteFile(journalPath, []byte(interrupted), 0o640); err != nil {
		t.Fatal(err)
	}

	out, code := captureStdout(t, func() int {
		return run([]string{"install", "--output", "json", "--state-dir", stateDir})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(out, "txn-crashed") {
		t.Errorf("expected the blocked result to reference the interrupted transaction, got: %s", out)
	}

	_, code = captureStdout(t, func() int {
		return run([]string{"repair", "--output", "json", "--state-dir", stateDir})
	})
	if code != 1 {
		t.Errorf("expected repair to proceed to its own (not-yet-implemented) body, got exit code %d", code)
	}
}
