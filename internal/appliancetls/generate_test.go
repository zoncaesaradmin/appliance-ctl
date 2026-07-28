package appliancetls_test

import (
	"crypto/x509"
	"net"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/appliancetls"
)

func TestBuildSANs_FQDNAndIPAndExtras(t *testing.T) {
	sans := appliancetls.BuildSANs("artifact-dns-1.appliance.internal", "192.0.2.10", []string{
		"192.0.2.11",
		"extra.example.internal",
		"artifact-dns-1.appliance.internal", // duplicate
	})
	if len(sans.DNSNames) != 2 || sans.DNSNames[0] != "artifact-dns-1.appliance.internal" || sans.DNSNames[1] != "extra.example.internal" {
		t.Fatalf("DNSNames = %#v", sans.DNSNames)
	}
	if len(sans.IPAddresses) != 2 {
		t.Fatalf("IPAddresses = %#v", sans.IPAddresses)
	}
}

func TestGenerateCAAndIssueLeaf_RoundTrip(t *testing.T) {
	caCert, caKey, err := appliancetls.GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	sans := appliancetls.SANs{
		DNSNames:    []string{"registry1.appliance.internal"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.10")},
	}
	leafCert, leafKey, err := appliancetls.IssueLeaf(caCert, caKey, sans)
	if err != nil {
		t.Fatal(err)
	}
	if len(leafKey) == 0 {
		t.Fatal("expected leaf key PEM")
	}
	cert, err := appliancetls.ParseCertificatePEM(leafCert)
	if err != nil {
		t.Fatal(err)
	}
	if !sans.Equal(cert) {
		t.Fatalf("leaf SANs mismatch: dns=%v ips=%v", cert.DNSNames, cert.IPAddresses)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caCert) {
		t.Fatal("append CA")
	}
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "registry1.appliance.internal", Roots: roots}); err != nil {
		t.Fatalf("verify FQDN: %v", err)
	}
}
