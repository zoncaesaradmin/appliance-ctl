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
	"strconv"
	"strings"

	"github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"
	"github.com/zoncaesaradmin/appliance-ctl/internal/redact"
)

var version = "dev"

const defaultStateDir = "/var/lib/zon/state"

// System paths for the K3s adapter. These are fixed, real system
// locations (not derived from --state-dir), matching where a production
// host actually needs them.
const (
	defaultK3sConfigPath       = "/etc/rancher/k3s/config.yaml"
	defaultK3sRegistriesPath   = "/etc/rancher/k3s/registries.yaml"
	defaultK3sDataDir          = "/var/lib/rancher/k3s"
	defaultK3sCNINetworkDir    = "/var/lib/cni/networks/cbr0"
	defaultK3sUnitPath         = "/etc/systemd/system/k3s.service"
	defaultK3sBinaryDestPath   = "/usr/local/bin/k3s"
	defaultKubectlSymlinkPath  = "/usr/local/bin/kubectl"
	defaultZonctlLauncherPath  = "/usr/local/bin/zonctl"
	defaultZonctlRealPath      = "/usr/local/lib/zon/bin/zonctl-real"
	defaultHostAgentBinaryPath = "/usr/local/lib/zon/bin/appliance-host-agentd"
	defaultHostAgentUnitPath   = "/etc/systemd/system/zon-host-agent.service"
	defaultHostAgentUnitName   = "zon-host-agent.service"
	defaultHostAgentSocketPath = "/run/zon/host-agent/agent.sock"
	defaultHostAgentLogPath    = "/data/zon/logs/host-agent/host-agentd.log"
	defaultKubeconfigPath      = "/etc/rancher/k3s/k3s.yaml"
	defaultK3sUnitName         = "k3s.service"
	defaultPublicKeyPath       = "/etc/zon/keys/release-signing.pub"
	defaultChartReleaseName    = "appliance"
	defaultChartNamespace      = "control"
	defaultWorkspaceRootDir    = "/data/zon/workspaces"
)

var defaultK3sCNIInterfaces = []string{"cni0", "flannel.1"}

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
	applianceProfile    string
	buildCatalogPath    string
	nodeName            string
	applianceName       string
	dnsZone             string
	tlsSANs             []string
	preserveFailedState bool
	backupID            string
	confirm             string
	acknowledgeDataLoss bool
	forceDataLoss       bool
	wipeWorkspaces      bool
	forceAdopt          bool
	// Optional image-pull registry (K3s registries.yaml). Host empty = omit.
	imagePullRegistry             string
	imagePullRegistryUsernameEnv  string
	imagePullRegistryTokenEnv     string
	imagePullRegistryTLSVerifyEnv string
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

type stringListFlag []string

func (f *stringListFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringListFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	*f = append(*f, value)
	return nil
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
	applianceProfile := fs.String("appliance-profile", "", "product-facing appliance profile to pass into the control plane (core, builder, storage, landns, storage-landns, builder-landns, builder-storage-landns); install defaults to core and upgrade preserves the installed profile when omitted")
	buildCatalogPath := fs.String("build-catalog", "", "path to developer workflow build catalog JSON/YAML to pass as product config into the control plane")
	nodeName := fs.String("node-name", "", "K3s node name (defaults to the host's hostname)")
	applianceName := fs.String("appliance-name", "", "product LAN instance label (single DNS label); FQDN becomes <name>.<dns-zone> for TLS and canonical origin (required for install; upgrade preserves installed value when omitted)")
	dnsZone := fs.String("dns-zone", "", "LAN DNS zone for appliance identity and landns CoreDNS (default appliance.internal)")
	var tlsSANs stringListFlag
	fs.Var(&tlsSANs, "tls-san", "additional TLS subjectAltName to include on the appliance certificate; repeatable (for example a raw IP)")
	preserveFailedState := fs.Bool("preserve-failed-state", false, "debug mode: do not roll back a failed install or upgrade; preserve the partial target state for investigation")
	backupID := fs.String("backup-id", "", "backup identifier to restore from (required for restore; optionally the verified recovery point for factory-reset)")
	confirm := fs.String("confirm", "", "confirmation token acknowledging this destructive operation (required for uninstall/factory-reset)")
	acknowledgeDataLoss := fs.Bool("acknowledge-data-loss", false, "explicitly acknowledge permanent data loss (required for factory-reset)")
	forceDataLoss := fs.Bool("force-data-loss", false, "override the requirement for a verified recent backup before factory-reset (still requires --acknowledge-data-loss)")
	wipeWorkspaces := fs.Bool("wipe-workspaces", false, "factory-reset only: also remove builder workspaces under /data/zon/workspaces")
	forceAdopt := fs.Bool("force-adopt", false, "take ownership of an existing K3s cluster even if it isn't obviously safe to adopt (unhealthy and/or carrying foreign workloads)")
	imagePullRegistry := fs.String("image-pull-registry", "", "optional private registry host for K3s containerd pulls (writes /etc/rancher/k3s/registries.yaml); empty keeps preload-only")
	imagePullRegistryUsernameEnv := fs.String("image-pull-registry-username-env", "", "env var name holding the image-pull registry username (required when --image-pull-registry is set; e.g. DEV_REGISTRY_USER)")
	imagePullRegistryTokenEnv := fs.String("image-pull-registry-token-env", "", "env var name holding the image-pull registry password/token (required when --image-pull-registry is set; e.g. DEV_REGISTRY_TOKEN)")
	imagePullRegistryTLSVerifyEnv := fs.String("image-pull-registry-tls-verify-env", "", "env var name holding true|false for registry TLS verify (optional; default true; e.g. DEV_REGISTRY_TLS_VERIFY)")
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
		dryRun:                        *dryRun,
		output:                        *output,
		stateDir:                      *stateDir,
		configPath:                    *configPath,
		bundleDir:                     *bundleDir,
		publicKey:                     *publicKey,
		applianceProfile:              *applianceProfile,
		buildCatalogPath:              *buildCatalogPath,
		nodeName:                      *nodeName,
		applianceName:                 *applianceName,
		dnsZone:                       *dnsZone,
		tlsSANs:                       append([]string(nil), tlsSANs...),
		preserveFailedState:           *preserveFailedState,
		backupID:                      *backupID,
		confirm:                       *confirm,
		acknowledgeDataLoss:           *acknowledgeDataLoss,
		forceDataLoss:                 *forceDataLoss,
		wipeWorkspaces:                *wipeWorkspaces,
		forceAdopt:                    *forceAdopt,
		imagePullRegistry:             *imagePullRegistry,
		imagePullRegistryUsernameEnv:  *imagePullRegistryUsernameEnv,
		imagePullRegistryTokenEnv:     *imagePullRegistryTokenEnv,
		imagePullRegistryTLSVerifyEnv: *imagePullRegistryTLSVerifyEnv,
	}

	logger := newLogger(redact.New(), opts.output)
	result := dispatch(spec, opts, logger)
	return emit(result, opts.output)
}

func installTLSSANs(opts cliOptions) []string {
	fqdn := ""
	if identity, err := productconfig.ResolveApplianceIdentity(opts.applianceName, opts.dnsZone); err == nil {
		fqdn = identity.FQDN
	}
	extra := append([]string(nil), opts.tlsSANs...)
	// Always include management AP SANs and hostname.local so day-2 mDNS /
	// Wi-Fi AP enablement works with the install-time certificate
	// (https://manage.ap/, https://10.42.0.1/, https://<host>.local/).
	extra = append([]string{
		productconfig.WifiAPManagementHostname,
		productconfig.WifiAPManagementAddress,
	}, extra...)
	if san := hostMDNSTLSSAN(opts.nodeName); san != "" {
		extra = append([]string{san}, extra...)
	}
	return effectiveTLSSANs(opts.nodeName, fqdn, extra...)
}

func effectiveTLSSANs(nodeName, fqdn string, extra ...string) []string {
	var out []string
	seen := map[string]struct{}{}
	appendUnique := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}

	appendUnique(fqdn)
	appendUnique(nodeName)
	for _, san := range extra {
		appendUnique(san)
	}
	return out
}

func hostMDNSTLSSAN(nodeName string) string {
	shortHost := strings.ToLower(strings.TrimSpace(nodeName))
	shortHost = strings.TrimSuffix(shortHost, ".local")
	shortHost = strings.TrimSuffix(shortHost, ".")
	if shortHost == "" {
		return ""
	}
	if strings.Contains(shortHost, ".") {
		shortHost = strings.SplitN(shortHost, ".", 2)[0]
	}
	if _, err := productconfig.NormalizeApplianceName(shortHost); err != nil {
		return ""
	}
	return shortHost + ".local"
}

func parseOptionalBool(value string) (bool, bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return false, false, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, true, err
	}
	return parsed, true, nil
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
