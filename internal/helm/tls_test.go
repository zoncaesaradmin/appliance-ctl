package helm_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/helm"
)

func TestEnsureApplianceTLSSecrets_CreatesCAAndTLSInControlAndArtifacts(t *testing.T) {
	var (
		caCreated    bool
		tlsCreated   []string
		leafCertPath string
	)
	secrets := map[string]map[string][]byte{}

	run := func(_ context.Context, name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(call, "get namespace"):
			return "Active", nil
		case strings.Contains(call, "get secret") && contains(args, "json"):
			ns := flagValue(args, "--namespace")
			secret := secretNameFromGet(args)
			data, ok := secrets[ns+"/"+secret]
			if !ok {
				return "", fmt.Errorf("secrets %q not found", secret)
			}
			encoded := map[string]string{}
			for k, v := range data {
				encoded[k] = base64.StdEncoding.EncodeToString(v)
			}
			payload, _ := json.Marshal(map[string]any{"data": encoded})
			return string(payload), nil
		case strings.Contains(call, "create secret generic appliance-ca"):
			ns := flagValue(args, "--namespace")
			entry := map[string][]byte{}
			for _, arg := range args {
				if strings.HasPrefix(arg, "--from-file=") {
					path := strings.TrimPrefix(arg, "--from-file=")
					content, err := os.ReadFile(path)
					if err != nil {
						return "", err
					}
					entry[filepathBase(path)] = content
				}
			}
			secrets[ns+"/appliance-ca"] = entry
			caCreated = true
			return "", nil
		case strings.Contains(call, "create secret tls appliance-tls"):
			ns := flagValue(args, "--namespace")
			entry := map[string][]byte{}
			for _, arg := range args {
				if strings.HasPrefix(arg, "--cert=") {
					path := strings.TrimPrefix(arg, "--cert=")
					leafCertPath = path
					content, err := os.ReadFile(path)
					if err != nil {
						return "", err
					}
					entry["tls.crt"] = content
				}
				if strings.HasPrefix(arg, "--key=") {
					path := strings.TrimPrefix(arg, "--key=")
					content, err := os.ReadFile(path)
					if err != nil {
						return "", err
					}
					entry["tls.key"] = content
				}
			}
			secrets[ns+"/appliance-tls"] = entry
			tlsCreated = append(tlsCreated, ns)
			return "", nil
		case strings.Contains(call, "delete secret"):
			ns := flagValue(args, "--namespace")
			secret := args[len(args)-1]
			if secret == "--ignore-not-found" {
				secret = args[len(args)-2]
			}
			delete(secrets, ns+"/"+secret)
			return "", nil
		default:
			return "", fmt.Errorf("unexpected call: %s", call)
		}
	}

	prepared, err := helm.EnsureApplianceTLSSecrets(context.Background(), run, "/kubeconfig", helm.ApplianceTLSOptions{
		ControlNamespace:  "ace-apps",
		ArtifactNamespace: "artifacts",
		IncludeArtifacts:  true,
		FQDN:              "artifact-dns-1.appliance.internal",
		NodeIPv4:          "192.0.2.10",
		ExtraSANs:         []string{"192.0.2.11"},
	})
	if err != nil {
		t.Fatalf("EnsureApplianceTLSSecrets: %v", err)
	}
	if !caCreated {
		t.Fatal("expected appliance-ca create")
	}
	if len(tlsCreated) != 2 {
		t.Fatalf("tls created in %#v, want control+artifacts", tlsCreated)
	}
	if len(prepared.Checks) != 1 || prepared.Checks[0].Status == "" {
		t.Fatalf("checks = %#v", prepared.Checks)
	}

	leafPEM, err := os.ReadFile(leafCertPath)
	if err != nil {
		// leaf path was under temp dir already removed; read from secret map
		leafPEM = secrets["ace-apps/appliance-tls"]["tls.crt"]
	}
	block, _ := pem.Decode(leafPEM)
	if block == nil {
		t.Fatal("decode leaf PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "artifact-dns-1.appliance.internal" {
		t.Fatalf("DNSNames = %#v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 2 {
		t.Fatalf("IPAddresses = %#v", cert.IPAddresses)
	}

	// Second call should reuse CA and skip TLS recreate when SANs match.
	caCreated = false
	tlsCreated = nil
	prepared, err = helm.EnsureApplianceTLSSecrets(context.Background(), run, "/kubeconfig", helm.ApplianceTLSOptions{
		ControlNamespace:  "ace-apps",
		ArtifactNamespace: "artifacts",
		IncludeArtifacts:  true,
		FQDN:              "artifact-dns-1.appliance.internal",
		NodeIPv4:          "192.0.2.10",
		ExtraSANs:         []string{"192.0.2.11"},
	})
	if err != nil {
		t.Fatalf("second EnsureApplianceTLSSecrets: %v", err)
	}
	if caCreated {
		t.Fatal("CA should be reused")
	}
	if len(tlsCreated) != 0 {
		t.Fatalf("TLS should be unchanged, got creates %#v", tlsCreated)
	}
	if !strings.Contains(prepared.Checks[0].Message, "already covers") {
		t.Fatalf("message = %q", prepared.Checks[0].Message)
	}
}

func flagValue(args []string, name string) string {
	for i, arg := range args {
		if arg == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func secretNameFromGet(args []string) string {
	for i, arg := range args {
		if arg == "secret" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func filepathBase(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}
