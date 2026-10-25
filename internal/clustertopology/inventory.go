// Package clustertopology validates the operator-supplied, host-specific
// inventory for an embedded-etcd appliance with one or three active servers.
// It contains no
// credentials and is deliberately separate from the portable release bundle.
package clustertopology

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
)

const EmbeddedEtcdV1 = "embedded-etcd-v1"

// ThreeServerEtcdV1 is retained as an internal symbol while the coordinator
// and its tests are generalized. Its wire value is the one signed embedded
// etcd contract, valid for either a one- or three-server inventory.
const ThreeServerEtcdV1 = EmbeddedEtcdV1

const maxInventoryBytes = 64 * 1024

var nodeNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Inventory is install-time topology input, not a release artifact. Its
// endpoints are one or three directly reachable server addresses. A
// three-server client retries another listed endpoint; this topology does not
// introduce a virtual address, load balancer, or other failover front end.
type Inventory struct {
	Topology      string `json:"topology"`
	BootstrapNode string `json:"bootstrapNode"`
	Nodes         []Node `json:"nodes"`
}

type Node struct {
	Name string `json:"name"`
	// Address is the server's reachable IPv4 address for K3s API and etcd
	// traffic. It may be an RFC1918/LAN address or a directly assigned VPS
	// address; all configured entries are independently usable API endpoints.
	Address string `json:"address"`
}

// Load accepts one small JSON object with no unknown fields or trailing data.
func Load(path string) (Inventory, error) {
	if strings.TrimSpace(path) == "" {
		return Inventory{}, errors.New("cluster inventory: file path is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return Inventory{}, fmt.Errorf("cluster inventory: open: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Inventory{}, fmt.Errorf("cluster inventory: stat: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxInventoryBytes {
		return Inventory{}, errors.New("cluster inventory: file must be regular and at most 64 KiB")
	}
	dec := json.NewDecoder(io.LimitReader(f, maxInventoryBytes+1))
	dec.DisallowUnknownFields()
	var inventory Inventory
	if err := dec.Decode(&inventory); err != nil {
		return Inventory{}, fmt.Errorf("cluster inventory: decode: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Inventory{}, errors.New("cluster inventory: trailing data or file too large")
	}
	if err := inventory.Validate(); err != nil {
		return Inventory{}, err
	}
	return inventory, nil
}

// Validate checks the product topology and address contract without making
// network calls. Reachability, TLS, and port checks are later host preflight
// gates, not claims made by this static check.
func (in Inventory) Validate() error {
	if in.Topology != EmbeddedEtcdV1 {
		return fmt.Errorf("cluster inventory: topology must be %q", EmbeddedEtcdV1)
	}
	if len(in.Nodes) != 1 && len(in.Nodes) != 3 {
		return errors.New("cluster inventory: exactly one or three server nodes are required")
	}
	if !nodeNamePattern.MatchString(in.BootstrapNode) {
		return errors.New("cluster inventory: bootstrapNode must be a DNS-label node name")
	}
	names := make(map[string]struct{}, 3)
	addresses := make(map[string]struct{}, 3)
	for _, node := range in.Nodes {
		if !nodeNamePattern.MatchString(node.Name) {
			return fmt.Errorf("cluster inventory: invalid node name %q", node.Name)
		}
		if _, duplicate := names[node.Name]; duplicate {
			return fmt.Errorf("cluster inventory: duplicate node name %q", node.Name)
		}
		names[node.Name] = struct{}{}
		address, err := netip.ParseAddr(node.Address)
		if err != nil || !address.Is4() || !address.IsGlobalUnicast() {
			return fmt.Errorf("cluster inventory: node %q requires a reachable unicast IPv4 address", node.Name)
		}
		if _, duplicate := addresses[address.String()]; duplicate {
			return fmt.Errorf("cluster inventory: duplicate server address %q", address)
		}
		addresses[address.String()] = struct{}{}
	}
	if _, exists := names[in.BootstrapNode]; !exists {
		return errors.New("cluster inventory: bootstrapNode must name one of the configured servers")
	}
	return nil
}

// APIEndpoints returns the direct API URLs. It deliberately does not
// manufacture a virtual address: clients that need N-1 availability must try
// these endpoints in order. The bootstrap address is first so peers can join
// the initial server before any other member exists.
func (in Inventory) APIEndpoints() []string {
	if err := in.Validate(); err != nil {
		return nil
	}
	endpoints := make([]string, 0, len(in.Nodes))
	for _, node := range in.Nodes {
		if node.Name == in.BootstrapNode {
			endpoints = append(endpoints, "https://"+node.Address+":6443")
			break
		}
	}
	for _, node := range in.Nodes {
		if node.Name != in.BootstrapNode {
			endpoints = append(endpoints, "https://"+node.Address+":6443")
		}
	}
	return endpoints
}

func (in Inventory) BootstrapAPIEndpoint() string {
	endpoints := in.APIEndpoints()
	if len(endpoints) == 0 {
		return ""
	}
	return endpoints[0]
}

// APISANs returns the direct IPv4 addresses that must all authenticate as
// Kubernetes API endpoints. This lets a caller retry another live server
// without a shared floating IP or a load balancer.
func (in Inventory) APISANs() []string {
	if err := in.Validate(); err != nil {
		return nil
	}
	sans := make([]string, 0, len(in.Nodes))
	for _, node := range in.Nodes {
		sans = append(sans, node.Address)
	}
	return sans
}

func (in Inventory) HasNode(name string) bool {
	for _, node := range in.Nodes {
		if node.Name == name {
			return true
		}
	}
	return false
}

// Fingerprint is a formatting-independent identity for the desired
// install-time topology. It contains no secrets and is safe for a receipt.
func (in Inventory) Fingerprint() (string, error) {
	if err := in.Validate(); err != nil {
		return "", err
	}
	canonicalInventory := in
	canonicalInventory.Nodes = append([]Node(nil), in.Nodes...)
	sort.Slice(canonicalInventory.Nodes, func(i, j int) bool {
		return canonicalInventory.Nodes[i].Name < canonicalInventory.Nodes[j].Name
	})
	canonical, err := json.Marshal(canonicalInventory)
	if err != nil {
		return "", fmt.Errorf("cluster inventory: encode fingerprint: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// ValidateLocalAddress proves that the inventory's private peer address for
// this node is actually assigned to a local interface. This avoids a host
// advertising another server's address.
func (in Inventory) ValidateLocalAddress(name string, local []netip.Addr) error {
	var expected string
	for _, node := range in.Nodes {
		if node.Name == name {
			expected = node.Address
			break
		}
	}
	if expected == "" {
		return fmt.Errorf("cluster inventory: node %q is not in the inventory", name)
	}
	for _, address := range local {
		if address.Is4() && address.String() == expected {
			return nil
		}
	}
	return fmt.Errorf("cluster inventory: server address for node %q is not assigned to a local interface", name)
}

// LocalAddresses reads interface addresses without changing host state.
func LocalAddresses() ([]netip.Addr, error) {
	interfaceAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("cluster inventory: list local interfaces: %w", err)
	}
	addresses := make([]netip.Addr, 0, len(interfaceAddrs))
	for _, addr := range interfaceAddrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if parsed, ok := netip.AddrFromSlice(ipNet.IP); ok {
			addresses = append(addresses, parsed.Unmap())
		}
	}
	return addresses, nil
}
