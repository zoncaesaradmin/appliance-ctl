package buildercreds

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/cli"
	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
	"gopkg.in/yaml.v3"
)

const (
	Namespace = "appliance-builds"
	baseDir   = "builder-credentials"
)

type Credential struct {
	ID                   string
	GitHost              string
	Namespace            string
	SecretName           string
	KnownHostsSecretName string
	PrivateKeyPath       string
	PublicKeyPath        string
	KnownHostsPath       string
}

type catalogDocument struct {
	SourceCredentials []catalogSourceCredential `yaml:"sourceCredentials" json:"sourceCredentials"`
}

type catalogSourceCredential struct {
	ID      string `yaml:"id" json:"id"`
	GitHost string `yaml:"gitHost" json:"gitHost"`
}

func Load(path, stateDir string) ([]Credential, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("builder credentials: read build catalog %s: %w", path, err)
	}
	var doc catalogDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("builder credentials: parse build catalog %s: %w", path, err)
	}
	if len(doc.SourceCredentials) == 0 {
		return nil, nil
	}
	root := filepath.Join(strings.TrimSpace(stateDir), baseDir)
	out := make([]Credential, 0, len(doc.SourceCredentials))
	for _, item := range doc.SourceCredentials {
		id := sanitizeIDSegment(item.ID)
		host := strings.TrimSpace(item.GitHost)
		if id == "" || host == "" {
			continue
		}
		dir := filepath.Join(root, id)
		out = append(out, Credential{
			ID:                   id,
			GitHost:              host,
			Namespace:            Namespace,
			SecretName:           secretName(id),
			KnownHostsSecretName: knownHostsSecretName(id),
			PrivateKeyPath:       filepath.Join(dir, "id_ed25519"),
			PublicKeyPath:        filepath.Join(dir, "id_ed25519.pub"),
			KnownHostsPath:       filepath.Join(dir, "known_hosts"),
		})
	}
	return out, nil
}

func Prepare(ctx context.Context, run cli.Runner, creds []Credential) ([]evidence.Check, error) {
	if run == nil {
		run = cli.Exec
	}
	var checks []evidence.Check
	for _, cred := range creds {
		keyCheck, err := ensureKeypair(ctx, run, cred)
		checks = append(checks, keyCheck)
		if err != nil {
			return checks, err
		}
		hostCheck, err := ensureKnownHosts(ctx, run, cred)
		checks = append(checks, hostCheck)
		if err != nil {
			return checks, err
		}
	}
	return checks, nil
}

func ensureKeypair(ctx context.Context, run cli.Runner, cred Credential) (evidence.Check, error) {
	check := newCheck("builder-source-key-" + sanitizeIDSegment(cred.ID))
	if err := os.MkdirAll(filepath.Dir(cred.PrivateKeyPath), 0o700); err != nil {
		check.Status = evidence.StatusFail
		check.Message = err.Error()
		return check, fmt.Errorf("builder credentials: create directory for %s: %w", cred.ID, err)
	}
	if readableFile(cred.PrivateKeyPath) && readableFile(cred.PublicKeyPath) {
		check.Status = evidence.StatusPass
		check.Message = fmt.Sprintf("builder source keypair ready for %s (%s)", cred.ID, cred.PublicKeyPath)
		return check, nil
	}
	if !readableFile(cred.PrivateKeyPath) {
		if _, err := run(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", cred.PrivateKeyPath); err != nil {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			return check, fmt.Errorf("builder credentials: generate keypair for %s: %w", cred.ID, err)
		}
	}
	if !readableFile(cred.PublicKeyPath) {
		pub, err := run(ctx, "ssh-keygen", "-y", "-f", cred.PrivateKeyPath)
		if err != nil {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			return check, fmt.Errorf("builder credentials: derive public key for %s: %w", cred.ID, err)
		}
		if err := os.WriteFile(cred.PublicKeyPath, []byte(strings.TrimSpace(pub)+"\n"), 0o644); err != nil {
			check.Status = evidence.StatusFail
			check.Message = err.Error()
			return check, fmt.Errorf("builder credentials: write public key for %s: %w", cred.ID, err)
		}
	}
	check.Status = evidence.StatusPass
	check.Message = fmt.Sprintf("builder source keypair ready for %s (%s)", cred.ID, cred.PublicKeyPath)
	return check, nil
}

func ensureKnownHosts(ctx context.Context, run cli.Runner, cred Credential) (evidence.Check, error) {
	check := newCheck("builder-known-hosts-" + sanitizeIDSegment(cred.ID))
	if readableFile(cred.KnownHostsPath) {
		check.Status = evidence.StatusPass
		check.Message = fmt.Sprintf("builder known_hosts ready for %s (%s)", cred.ID, cred.KnownHostsPath)
		return check, nil
	}
	host, port := splitHostPort(cred.GitHost)
	args := []string{"-T", "5", "-t", "rsa,ecdsa,ed25519"}
	if port != "" {
		args = append(args, "-p", port)
	}
	args = append(args, host)
	out, err := run(ctx, "ssh-keyscan", args...)
	if err != nil {
		check.Status = evidence.StatusFail
		check.Message = err.Error()
		return check, fmt.Errorf("builder credentials: scan SSH host key for %s: %w", cred.GitHost, err)
	}
	if strings.TrimSpace(out) == "" {
		check.Status = evidence.StatusFail
		check.Message = "ssh-keyscan returned no host keys"
		return check, fmt.Errorf("builder credentials: scan SSH host key for %s: no host keys returned", cred.GitHost)
	}
	if err := os.WriteFile(cred.KnownHostsPath, []byte(out), 0o644); err != nil {
		check.Status = evidence.StatusFail
		check.Message = err.Error()
		return check, fmt.Errorf("builder credentials: write known_hosts for %s: %w", cred.ID, err)
	}
	check.Status = evidence.StatusPass
	check.Message = fmt.Sprintf("builder known_hosts ready for %s (%s)", cred.ID, cred.KnownHostsPath)
	return check, nil
}

func splitHostPort(host string) (string, string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", ""
	}
	if cut := strings.LastIndex(host, ":"); cut > 0 && cut < len(host)-1 {
		if _, err := strconv.Atoi(host[cut+1:]); err == nil {
			return host[:cut], host[cut+1:]
		}
	}
	return host, ""
}

func newCheck(id string) evidence.Check {
	return evidence.Check{
		ID:              id,
		Category:        "builder",
		Timestamp:       time.Now().UTC(),
		Idempotent:      true,
		SecretsRedacted: true,
	}
}

func readableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}

func secretName(id string) string {
	return "builder-git-" + sanitizeIDSegment(id) + "-key"
}

func knownHostsSecretName(id string) string {
	return "builder-git-" + sanitizeIDSegment(id) + "-known-hosts"
}

func sanitizeIDSegment(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "source"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	name := strings.Trim(b.String(), "-")
	if name == "" {
		return "source"
	}
	return name
}
