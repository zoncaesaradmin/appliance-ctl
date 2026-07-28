// Package appliancetls generates the installer-owned appliance CA and
// HTTPS leaf certificate used by Traefik (Secret appliance-tls).
package appliancetls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	caValidity   = 10 * 365 * 24 * time.Hour
	leafValidity = 2 * 365 * 24 * time.Hour
)

// Material is PEM-encoded CA and leaf material for Kubernetes Secrets.
type Material struct {
	CACertPEM   []byte
	CAKeyPEM    []byte
	LeafCertPEM []byte
	LeafKeyPEM  []byte
}

// SANs are the DNS names and IP addresses embedded in the leaf certificate.
type SANs struct {
	DNSNames    []string
	IPAddresses []net.IP
}

// BuildSANs derives leaf SANs from the appliance FQDN, preferred node IPv4,
// and any extra --tls-san values (DNS names or IPs).
func BuildSANs(fqdn, nodeIPv4 string, extras []string) SANs {
	var sans SANs
	seenDNS := map[string]struct{}{}
	seenIP := map[string]struct{}{}

	addDNS := func(name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return
		}
		if _, ok := seenDNS[name]; ok {
			return
		}
		seenDNS[name] = struct{}{}
		sans.DNSNames = append(sans.DNSNames, name)
	}
	addIP := func(raw string) {
		raw = strings.TrimSpace(raw)
		ip := net.ParseIP(raw)
		if ip == nil {
			return
		}
		key := ip.String()
		if _, ok := seenIP[key]; ok {
			return
		}
		seenIP[key] = struct{}{}
		sans.IPAddresses = append(sans.IPAddresses, ip)
	}

	addDNS(fqdn)
	addIP(nodeIPv4)
	for _, extra := range extras {
		extra = strings.TrimSpace(extra)
		if extra == "" {
			continue
		}
		if net.ParseIP(extra) != nil {
			addIP(extra)
			continue
		}
		addDNS(extra)
	}
	return sans
}

// Equal reports whether the certificate's SANs match the desired set
// (order-independent).
func (s SANs) Equal(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if len(s.DNSNames) != len(cert.DNSNames) || len(s.IPAddresses) != len(cert.IPAddresses) {
		return false
	}
	haveDNS := map[string]struct{}{}
	for _, name := range cert.DNSNames {
		haveDNS[strings.ToLower(name)] = struct{}{}
	}
	for _, name := range s.DNSNames {
		if _, ok := haveDNS[strings.ToLower(name)]; !ok {
			return false
		}
	}
	haveIP := map[string]struct{}{}
	for _, ip := range cert.IPAddresses {
		haveIP[ip.String()] = struct{}{}
	}
	for _, ip := range s.IPAddresses {
		if _, ok := haveIP[ip.String()]; !ok {
			return false
		}
	}
	return true
}

// GenerateCA creates a new ECDSA P-256 appliance CA.
func GenerateCA() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("appliancetls: generate CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("appliancetls: CA serial: %w", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Zon Appliance"},
			CommonName:   "Zon Appliance CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("appliancetls: create CA certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("appliancetls: marshal CA key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}

// IssueLeaf signs a server leaf certificate for sans using the appliance CA.
func IssueLeaf(caCertPEM, caKeyPEM []byte, sans SANs) (certPEM, keyPEM []byte, err error) {
	if len(sans.DNSNames) == 0 && len(sans.IPAddresses) == 0 {
		return nil, nil, fmt.Errorf("appliancetls: leaf requires at least one DNS name or IP SAN")
	}
	caCert, err := parseCertificatePEM(caCertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("appliancetls: parse CA certificate: %w", err)
	}
	caKey, err := parseECPrivateKeyPEM(caKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("appliancetls: parse CA key: %w", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("appliancetls: generate leaf key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("appliancetls: leaf serial: %w", err)
	}
	cn := "appliance"
	if len(sans.DNSNames) > 0 {
		cn = sans.DNSNames[0]
	} else {
		cn = sans.IPAddresses[0].String()
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Zon Appliance"},
			CommonName:   cn,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              append([]string(nil), sans.DNSNames...),
		IPAddresses:           append([]net.IP(nil), sans.IPAddresses...),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("appliancetls: create leaf certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, nil, fmt.Errorf("appliancetls: marshal leaf key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}

// ParseCertificatePEM parses the first CERTIFICATE PEM block.
func ParseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	return parseCertificatePEM(pemBytes)
}

func parseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseECPrivateKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no private key PEM block")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not ECDSA")
		}
		return ecKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %q", block.Type)
	}
}
