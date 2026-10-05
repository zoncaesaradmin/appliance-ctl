package state

import (
	"net"
	"net/url"
	"strings"
)

const defaultK3sAPIPort = "6443"

// APIURL is the K3s API on a prime's existing LAN IPv4. No extra VIP.
func APIURL(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	return "https://" + ip + ":" + defaultK3sAPIPort
}

// IPv4FromNodeName maps appliance node names such as 192-168-1-155 to
// 192.168.1.155. Dotted IPv4 names pass through. Other names are not IPs.
func IPv4FromNodeName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", false
	}
	if ip := net.ParseIP(name); ip != nil && ip.To4() != nil {
		return ip.To4().String(), true
	}
	parts := strings.Split(name, "-")
	if len(parts) != 4 {
		return "", false
	}
	joined := strings.Join(parts, ".")
	ip := net.ParseIP(joined)
	if ip == nil || ip.To4() == nil {
		return "", false
	}
	return ip.To4().String(), true
}

// NormalizeAPIEndpoint returns a comparable https://host:port form.
func NormalizeAPIEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return ""
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = defaultK3sAPIPort
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		host = ip.To4().String()
	}
	return "https://" + host + ":" + port
}

// KnownAPIEndpoints is every prime API URL recorded on this receipt.
func (c *Cluster) KnownAPIEndpoints() []string {
	if c == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(raw string) {
		normalized := NormalizeAPIEndpoint(raw)
		if normalized == "" {
			return
		}
		if _, ok := seen[normalized]; ok {
			return
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	add(c.ControlEndpoint)
	for _, endpoint := range c.ControlEndpoints {
		add(endpoint)
	}
	for _, node := range c.Nodes {
		if node.Role != NodeRoleControlPlane && !hasRole(node.Roles, NodeRoleControlPlane) {
			continue
		}
		if ip, ok := IPv4FromNodeName(node.Name); ok {
			add(APIURL(ip))
		}
	}
	return out
}

// AcceptsAPIEndpoint reports whether endpoint is a known prime API URL.
// An empty inventory accepts the first well-formed https URL (initial pin).
func (c *Cluster) AcceptsAPIEndpoint(endpoint string) bool {
	normalized := NormalizeAPIEndpoint(endpoint)
	if normalized == "" {
		return false
	}
	known := c.KnownAPIEndpoints()
	if len(known) == 0 {
		return true
	}
	for _, item := range known {
		if item == normalized {
			return true
		}
	}
	return false
}

// PrimeIPv4s returns LAN IPv4s for known prime API URLs and control-plane nodes.
func (c *Cluster) PrimeIPv4s() []string {
	seen := make(map[string]struct{})
	var out []string
	addIP := func(ip string) {
		ip = strings.TrimSpace(ip)
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() == nil {
			return
		}
		s := parsed.To4().String()
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, endpoint := range c.KnownAPIEndpoints() {
		if parsed, err := url.Parse(endpoint); err == nil {
			addIP(parsed.Hostname())
		}
	}
	return out
}

// AddAPIEndpoints records https://<ip>:6443 for each IPv4 without changing
// ControlEndpoint (the preferred join URL).
func (c *Cluster) AddAPIEndpoints(ips ...string) {
	if c == nil {
		return
	}
	seen := make(map[string]struct{})
	for _, existing := range c.ControlEndpoints {
		if normalized := NormalizeAPIEndpoint(existing); normalized != "" {
			seen[normalized] = struct{}{}
		}
	}
	if preferred := NormalizeAPIEndpoint(c.ControlEndpoint); preferred != "" {
		seen[preferred] = struct{}{}
	}
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil {
			continue
		}
		endpoint := APIURL(net.ParseIP(ip).To4().String())
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = struct{}{}
		c.ControlEndpoints = append(c.ControlEndpoints, endpoint)
	}
}

// SetPreferredAPI pins ControlEndpoint to ip and records it in ControlEndpoints.
func (c *Cluster) SetPreferredAPI(ip string) {
	if c == nil {
		return
	}
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil {
		return
	}
	c.ControlEndpoint = APIURL(net.ParseIP(ip).To4().String())
	c.AddAPIEndpoints(ip)
}

func hasRole(roles []string, want string) bool {
	for _, role := range roles {
		if role == want {
			return true
		}
	}
	return false
}
