package safelog

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func newTestLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	h := NewRedactingHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return slog.New(h), &buf
}

func TestRedactsByKey(t *testing.T) {
	lg, buf := newTestLogger()
	lg.Info("x", "email", "alice@example.com")
	out := buf.String()
	if !strings.Contains(out, `"email":"REDACTED"`) {
		t.Fatalf("output: %s", out)
	}
}

func TestRedactsEmailValueRegardlessOfKey(t *testing.T) {
	lg, buf := newTestLogger()
	lg.Info("x", "owner", "bob@example.com")
	out := buf.String()
	if !strings.Contains(out, `"owner":"REDACTED"`) {
		t.Fatalf("output: %s", out)
	}
}

func TestPassesThroughNonSensitive(t *testing.T) {
	lg, buf := newTestLogger()
	lg.Info("x", "request_id", "rid-123", "status", 200)
	out := buf.String()
	if !strings.Contains(out, `"request_id":"rid-123"`) {
		t.Fatalf("missing request_id: %s", out)
	}
}

func TestRedactsInGroup(t *testing.T) {
	lg, buf := newTestLogger()
	lg.Info("x", slog.Group("user", slog.String("email", "carol@example.com"), slog.String("name", "Carol")))
	out := buf.String()
	if !strings.Contains(out, `"email":"REDACTED"`) {
		t.Fatalf("output: %s", out)
	}
	if !strings.Contains(out, `"name":"Carol"`) {
		t.Fatalf("non-PII inside group must pass: %s", out)
	}
}

func TestWithAttrsRedacted(t *testing.T) {
	lg, buf := newTestLogger()
	lg = lg.With("token", "supersecret")
	lg.Info("x")
	out := buf.String()
	if !strings.Contains(out, `"token":"REDACTED"`) {
		t.Fatalf("output: %s", out)
	}
}
