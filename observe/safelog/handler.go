// Package safelog wraps an slog.Handler with attribute-level
// redaction so a stray slog.Info("...", "recipient", addr) cannot leak
// PII to logs. The denylist is built into the handler — callers do
// not have to remember to redact at every site.
//
// PII contract: this is a defence-in-depth layer. Callers MUST still
// avoid logging PII at the source where possible; the redactor is the
// safety net, not the primary control.
package safelog

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
)

// RedactedValue is the literal string substituted in for any matched
// attribute. We use a fixed sentinel rather than dropping the field so
// the operator can see redaction happened (vs missing data).
const RedactedValue = "REDACTED"

// defaultDenylist names every attribute key that, regardless of the
// value, is dropped before reaching the inner handler. Keys are
// matched case-insensitively. Reuse `defaultDenylist` rather than
// rebuilding it per call.
var defaultDenylist = func() map[string]struct{} {
	keys := []string{
		"email", "recipient", "to", "cc", "bcc", "from",
		"subject", "body", "html", "text",
		"api_key", "auth_key", "otp", "otp_mac",
		"password", "secret", "token", "authorization",
		"cookie", "set-cookie", "x-internal-token",
	}
	out := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		out[strings.ToLower(k)] = struct{}{}
	}
	return out
}()

// emailRe matches a string that contains an @ followed by a dot
// somewhere later — close enough to "email-shaped" that we redact it
// regardless of the attribute key. Imperfect by design: false positives
// (e.g. "ab@cd.localdomain") are acceptable; false negatives are not.
var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

type redactingHandler struct {
	inner slog.Handler
}

// NewRedactingHandler wraps `inner` so every record's attributes are
// rewritten with the package's denylist + email regex before being
// passed downstream.
func NewRedactingHandler(inner slog.Handler) slog.Handler {
	if inner == nil {
		return nil
	}
	return &redactingHandler{inner: inner}
}

func (h *redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(redactAttr(a))
		return true
	})
	return h.inner.Handle(ctx, out)
}

func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	red := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		red[i] = redactAttr(a)
	}
	return &redactingHandler{inner: h.inner.WithAttrs(red)}
}

func (h *redactingHandler) WithGroup(name string) slog.Handler {
	return &redactingHandler{inner: h.inner.WithGroup(name)}
}

func redactAttr(a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindGroup {
		grp := a.Value.Group()
		out := make([]slog.Attr, len(grp))
		for i, sub := range grp {
			out[i] = redactAttr(sub)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(out...)}
	}
	if _, denied := defaultDenylist[strings.ToLower(a.Key)]; denied {
		return slog.Attr{Key: a.Key, Value: slog.StringValue(RedactedValue)}
	}
	if a.Value.Kind() == slog.KindString {
		s := a.Value.String()
		if emailRe.MatchString(s) {
			return slog.Attr{Key: a.Key, Value: slog.StringValue(RedactedValue)}
		}
	}
	return a
}
