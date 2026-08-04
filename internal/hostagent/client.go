package hostagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// WifiAPManagementAddress is always included in install TLS SANs so the
// management AP URL https://10.42.0.1/ works when the feature is activated.
const WifiAPManagementAddress = "10.42.0.1"

// WifiAPStatus mirrors the host-agentd wifi-ap status JSON (no secrets).
type WifiAPStatus struct {
	Desired           bool   `json:"desired"`
	Actual            string `json:"actual"`
	Reason            string `json:"reason,omitempty"`
	SSID              string `json:"ssid,omitempty"`
	Iface             string `json:"iface,omitempty"`
	ManagementAddress string `json:"managementAddress"`
	Security          string `json:"security"`
	SupportedCapable  bool   `json:"supportedCapable"`
	Message           string `json:"message,omitempty"`
}

// WifiAPApplyRequest is the shared body for install and API apply.
type WifiAPApplyRequest struct {
	Desired  bool   `json:"desired"`
	PSK      string `json:"psk,omitempty"`
	SSIDBase string `json:"ssidBase,omitempty"`
}

// Client talks to appliance-host-agentd over its Unix socket.
type Client struct {
	SocketPath string
	HTTPClient *http.Client
	baseURL    string
}

// NewClient returns a client for the host agent daemon socket.
func NewClient(socketPath string) *Client {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		socketPath = "/run/zon/host-agent/agent.sock"
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{
		SocketPath: socketPath,
		baseURL:    "http://host-agentd",
		HTTPClient: &http.Client{Transport: transport, Timeout: 60 * time.Second},
	}
}

// ApplyWifiAP calls PUT /internal/v1/host/wifi-ap on host-agentd.
func (c *Client) ApplyWifiAP(ctx context.Context, req WifiAPApplyRequest) (WifiAPStatus, error) {
	var status WifiAPStatus
	if err := c.do(ctx, http.MethodPut, "/internal/v1/host/wifi-ap", req, &status); err != nil {
		return WifiAPStatus{}, err
	}
	return status, nil
}

// GetWifiAP calls GET /internal/v1/host/wifi-ap on host-agentd.
func (c *Client) GetWifiAP(ctx context.Context) (WifiAPStatus, error) {
	var status WifiAPStatus
	if err := c.do(ctx, http.MethodGet, "/internal/v1/host/wifi-ap", nil, &status); err != nil {
		return WifiAPStatus{}, err
	}
	return status, nil
}

// WaitReady polls the health endpoint until the daemon socket answers or timeout.
func (c *Client) WaitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if err := c.do(ctx, http.MethodGet, "/healthz", nil, nil); err == nil {
			return nil
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if last == nil {
		last = fmt.Errorf("host agent not ready")
	}
	return fmt.Errorf("hostagent: wait ready: %w", last)
}

func (c *Client) do(ctx context.Context, method, path string, body any, target any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("hostagent: encode %s: %w", path, err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("hostagent: request %s: %w", path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("hostagent: %s %s via %s: %w", method, path, c.SocketPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("hostagent: %s %s status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if target == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("hostagent: decode %s: %w", path, err)
	}
	return nil
}
