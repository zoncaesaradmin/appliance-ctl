// Command zonctl is the versioned lifecycle entrypoint for the Zon
// platform appliance. It wires subcommand dispatch, the host-wide
// installer lock, the transaction journal, dry-run, and redacted
// logging. See docs/release-plan.md.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/zoncaesaradmin/appliance-ctl/internal/redact"
)

var version = "dev"

const defaultStateDir = "/var/lib/zon"

// System paths for the K3s adapter. These are fixed, real system
// locations (not derived from --state-dir), matching where a production
// host actually needs them.
const (
	defaultK3sConfigPath      = "/etc/rancher/k3s/config.yaml"
	defaultK3sDataDir         = "/var/lib/rancher/k3s"
	defaultK3sUnitPath        = "/etc/systemd/system/k3s.service"
	defaultK3sBinaryDestPath  = "/usr/local/bin/k3s"
	defaultKubectlSymlinkPath = "/usr/local/bin/kubectl"
	defaultZonctlLauncherPath = "/usr/local/bin/zonctl"
	defaultZonctlRealPath     = "/usr/local/lib/zon/bin/zonctl-real"
	defaultKubeconfigPath     = "/etc/rancher/k3s/k3s.yaml"
	defaultK3sUnitName        = "k3s.service"
	defaultPublicKeyPath      = "/etc/zon/keys/release-signing.pub"
	defaultChartReleaseName   = "zon"
	defaultChartNamespace     = "zon"
)

// cliOptions carries every flag value dispatch needs. Only bundleDir and
// publicKeyPath are install-specific; the rest are shared or unused by
// most commands (unused flags are harmless).
type cliOptions struct {
	dryRun              bool
	output              string
	stateDir            string
	configPath          string
	bundleDir           string
	publicKey           string
	nodeName            string
	bootstrapAdminUser  string
	bootstrapPassStdin  bool
	backupID            string
	confirm             string
	acknowledgeDataLoss bool
	forceDataLoss       bool
	forceAdopt          bool
}

type commandSpec struct {
	name string
	// hostMutating commands take the host-wide lock and record a
	// transaction in the journal. Read-only and release-engineering
	// commands do not touch the live host and therefore skip that path.
	mutating bool
}

var commands = []commandSpec{
	{"assemble-bundle", false},
	{"preflight", false},
	{"install", true},
	{"status", false},
	{"verify", false},
	{"verify-bundle", false},
	{"backup", true},
	{"restore", true},
	{"upgrade", true},
	{"repair", true},
	{"support-bundle", false},
	{"uninstall", true},
	{"factory-reset", true},
}

func findCommand(name string) (commandSpec, bool) {
	for _, c := range commands {
		if c.name == name {
			return c, true
		}
	}
	return commandSpec{}, false
}

func usage() string {
	names := make([]string, len(commands))
	for i, c := range commands {
		names[i] = c.name
	}
	return "usage: zonctl <command> [--dry-run] [--output text|json] [--state-dir DIR]\n\ncommands:\n  " + strings.Join(names, "\n  ")
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, usage())
		return 2
	}

	name := args[0]
	spec, ok := findCommand(name)
	if !ok {
		fmt.Fprintf(os.Stderr, "zonctl: unknown command %q\n\n%s\n", name, usage())
		return 2
	}

	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "show what would happen without making changes")
	output := fs.String("output", "text", `output format: "text" or "json"`)
	stateDir := fs.String("state-dir", defaultStateDir, "directory holding the installer lock, transaction journal, and installed-state record")
	configPath := fs.String("config", "", "path to a bundle assembly config JSON file (required for assemble-bundle)")
	bundleDir := fs.String("bundle-dir", "", "path to an extracted signed appliance bundle directory (required for install/upgrade)")
	publicKey := fs.String("public-key", defaultPublicKeyPath, "path to the pinned release-signing public key for bundle verification")
	nodeName := fs.String("node-name", "", "K3s node name (defaults to the host's hostname)")
	bootstrapAdminUser := fs.String("bootstrap-admin-username", "admin", "username for the first administrator created during install")
	bootstrapPassStdin := fs.Bool("bootstrap-password-stdin", false, "read the first administrator password from stdin instead of prompting on the terminal")
	backupID := fs.String("backup-id", "", "backup identifier to restore from (required for restore; optionally the verified recovery point for factory-reset)")
	confirm := fs.String("confirm", "", "confirmation token acknowledging this destructive operation (required for uninstall/factory-reset)")
	acknowledgeDataLoss := fs.Bool("acknowledge-data-loss", false, "explicitly acknowledge permanent data loss (required for factory-reset)")
	forceDataLoss := fs.Bool("force-data-loss", false, "override the requirement for a verified recent backup before factory-reset (still requires --acknowledge-data-loss)")
	forceAdopt := fs.Bool("force-adopt", false, "take ownership of an existing K3s cluster even if it isn't obviously safe to adopt (unhealthy and/or carrying foreign workloads)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *output != "text" && *output != "json" {
		fmt.Fprintf(os.Stderr, "zonctl: invalid --output %q: must be \"text\" or \"json\"\n", *output)
		return 2
	}
	if *nodeName == "" {
		if h, err := os.Hostname(); err == nil {
			*nodeName = h
		}
	}

	opts := cliOptions{
		dryRun:              *dryRun,
		output:              *output,
		stateDir:            *stateDir,
		configPath:          *configPath,
		bundleDir:           *bundleDir,
		publicKey:           *publicKey,
		nodeName:            *nodeName,
		bootstrapAdminUser:  *bootstrapAdminUser,
		bootstrapPassStdin:  *bootstrapPassStdin,
		backupID:            *backupID,
		confirm:             *confirm,
		acknowledgeDataLoss: *acknowledgeDataLoss,
		forceDataLoss:       *forceDataLoss,
		forceAdopt:          *forceAdopt,
	}

	logger := newLogger(redact.New(), opts.output)
	result := dispatch(spec, opts, logger)
	return emit(result, opts.output)
}

func newLogger(r *redact.Redactor, output string) *slog.Logger {
	handlerOpts := &slog.HandlerOptions{Level: slog.LevelWarn}
	var base slog.Handler
	if output == "json" {
		base = slog.NewJSONHandler(os.Stderr, handlerOpts)
	} else {
		base = slog.NewTextHandler(os.Stderr, handlerOpts)
	}
	return slog.New(redact.NewHandler(base, r))
}
