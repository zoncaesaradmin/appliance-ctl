package redact_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/redact"
)

func TestHandler_RedactsMessageAndAttrs(t *testing.T) {
	var buf bytes.Buffer
	r := redact.New()
	r.Register("hunter2")
	r.Register("bearer-abc123")

	logger := slog.New(redact.NewHandler(slog.NewTextHandler(&buf, nil), r))
	logger.Info("logging in with password hunter2", "authToken", "bearer-abc123", "attempt", 3)

	out := buf.String()
	if strings.Contains(out, "hunter2") || strings.Contains(out, "bearer-abc123") {
		t.Errorf("expected secrets to be scrubbed from log output, got: %s", out)
	}
	if !strings.Contains(out, "attempt=3") {
		t.Errorf("expected non-secret attrs to pass through unchanged, got: %s", out)
	}
}

func TestHandler_RedactsGroupedAttrs(t *testing.T) {
	var buf bytes.Buffer
	r := redact.New()
	r.Register("top-secret-cert")

	logger := slog.New(redact.NewHandler(slog.NewTextHandler(&buf, nil), r))
	logger.Info("installed TLS material", slog.Group("tls", slog.String("cert", "top-secret-cert")))

	if strings.Contains(buf.String(), "top-secret-cert") {
		t.Errorf("expected secret nested in a group to be scrubbed, got: %s", buf.String())
	}
}

// Secrets registered before a logger derives bound attrs via With() must
// be scrubbed from those bound attrs too, not just from live call sites.
func TestHandler_WithAttrsRedactsAtBindTime(t *testing.T) {
	var buf bytes.Buffer
	r := redact.New()
	r.Register("bound-secret-value")

	base := slog.New(redact.NewHandler(slog.NewTextHandler(&buf, nil), r))
	bound := base.With("apiKey", "bound-secret-value")
	bound.Info("ready")

	if strings.Contains(buf.String(), "bound-secret-value") {
		t.Errorf("expected secret bound via With() to be scrubbed, got: %s", buf.String())
	}
}

func TestHandler_JSONOutputRedacted(t *testing.T) {
	var buf bytes.Buffer
	r := redact.New()
	r.Register("json-secret")

	logger := slog.New(redact.NewHandler(slog.NewJSONHandler(&buf, nil), r))
	logger.Info("message", "field", "json-secret")

	if strings.Contains(buf.String(), "json-secret") {
		t.Errorf("expected secret to be scrubbed from JSON output, got: %s", buf.String())
	}
}
