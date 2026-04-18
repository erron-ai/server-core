package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// mailRedactors reproduces the Mail product's table purely for core-level
// testing; the real Mail redactor table lives in the server package.
var mailRedactors = []Redactor{
	func(path string) (string, bool) {
		const prefix = "/v1/suppressions/"
		if strings.HasPrefix(path, prefix) {
			return "/v1/suppressions/:id", true
		}
		return path, false
	},
	func(path string) (string, bool) {
		const prefix = "/v1/secure/"
		if !strings.HasPrefix(path, prefix) {
			return path, false
		}
		rest := path[len(prefix):]
		if rest == "" {
			return path, false
		}
		if idx := strings.IndexByte(rest, '/'); idx >= 0 && rest[idx+1:] == "otp" {
			return "/v1/secure/:token/otp", true
		}
		return "/v1/secure/:token", true
	},
}

func TestRedactPath_NoRedactorsIsIdentity(t *testing.T) {
	t.Parallel()

	cases := []string{"/v1/emails", "/v1/secure/abc123", "/v1/suppressions/abc"}
	for _, in := range cases {
		if got := RedactPath(in); got != in {
			t.Fatalf("RedactPath(%q) with no redactors should be identity, got %q", in, got)
		}
	}
}

func TestRedactPath_WithRedactors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input string
		want  string
	}{
		{input: "/v1/emails", want: "/v1/emails"},
		{input: "/v1/secure/token123", want: "/v1/secure/:token"},
		{input: "/v1/secure/token123/otp", want: "/v1/secure/:token/otp"},
		{input: "/v1/suppressions/alice@example.com", want: "/v1/suppressions/:id"},
	}

	for _, tc := range cases {
		if got := RedactPath(tc.input, mailRedactors...); got != tc.want {
			t.Fatalf("RedactPath(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestEntryHashDeterministic(t *testing.T) {
	t.Parallel()

	orgID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	eventID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	event := Event{
		EventID:      eventID,
		EventType:    "http.request",
		RequestID:    "req-123",
		OrgID:        &orgID,
		ActorType:    "api_key",
		ActorID:      "key-123",
		Action:       "GET /v1/emails",
		Outcome:      "success",
		Method:       "GET",
		Path:         "/v1/emails",
		RoutePattern: "/v1/emails",
		StatusCode:   200,
		CreatedAt:    time.Unix(1710000000, 0).UTC(),
	}

	first := EntryHash(event, "prev-hash")
	second := EntryHash(event, "prev-hash")
	if first != second {
		t.Fatalf("EntryHash must be deterministic")
	}
	if first == EntryHash(event, "different-prev") {
		t.Fatalf("EntryHash should change when prev hash changes")
	}
}
