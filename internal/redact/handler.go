package redact

import (
	"context"
	"log/slog"
)

// Handler wraps an slog.Handler, redacting the message and every
// string-valued attribute (recursively through groups) before delegating.
//
// WithAttrs redacts against whatever secrets are registered at the time
// it is called, since those attrs are frozen into the returned handler.
// Register secrets before constructing loggers that carry them via
// .With(...) so they are caught; attrs passed directly to a log call
// (e.g. logger.Info(msg, "key", value)) are always redacted live, in
// Handle, regardless of registration order.
type Handler struct {
	next     slog.Handler
	redactor *Redactor
}

// NewHandler wraps next so every record it handles is redacted first.
func NewHandler(next slog.Handler, r *Redactor) *Handler {
	return &Handler{next: next, redactor: r}
}

func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *Handler) Handle(ctx context.Context, record slog.Record) error {
	redacted := slog.NewRecord(record.Time, record.Level, h.redactor.Redact(record.Message), record.PC)
	record.Attrs(func(a slog.Attr) bool {
		redacted.AddAttrs(h.redactAttr(a))
		return true
	})
	return h.next.Handle(ctx, redacted)
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redacted[i] = h.redactAttr(a)
	}
	return &Handler{next: h.next.WithAttrs(redacted), redactor: h.redactor}
}

func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{next: h.next.WithGroup(name), redactor: h.redactor}
}

func (h *Handler) redactAttr(a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindString:
		return slog.String(a.Key, h.redactor.Redact(a.Value.String()))
	case slog.KindGroup:
		group := a.Value.Group()
		redacted := make([]any, 0, len(group))
		for _, ga := range group {
			redacted = append(redacted, h.redactAttr(ga))
		}
		return slog.Group(a.Key, redacted...)
	default:
		return a
	}
}
