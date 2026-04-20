package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// sampleRedactors exercises the Redactor chain contract with two toy
// patterns. server-core ships zero product-specific route literals; real
// product redactor tables (for Mail, Forms, etc.) live in each consumer.
var sampleRedactors = []Redactor{
	func(path string) (string, bool) {
		const prefix = "/x/items/"
		if strings.HasPrefix(path, prefix) {
			return "/x/items/:id", true
		}
		return path, false
	},
	func(path string) (string, bool) {
		const prefix = "/x/doc/"
		if !strings.HasPrefix(path, prefix) {
			return path, false
		}
		rest := path[len(prefix):]
		if rest == "" {
			return path, false
		}
		if idx := strings.IndexByte(rest, '/'); idx >= 0 && rest[idx+1:] == "step" {
			return "/x/doc/:token/step", true
		}
		return "/x/doc/:token", true
	},
}

func TestRedactPath_NoRedactorsIsIdentity(t *testing.T) {
	t.Parallel()

	cases := []string{"/x/items", "/x/doc/abc123", "/x/items/abc"}
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
		{input: "/x/other", want: "/x/other"},
		{input: "/x/doc/token123", want: "/x/doc/:token"},
		{input: "/x/doc/token123/step", want: "/x/doc/:token/step"},
		{input: "/x/items/some-id", want: "/x/items/:id"},
	}

	for _, tc := range cases {
		if got := RedactPath(tc.input, sampleRedactors...); got != tc.want {
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
		Action:       "GET /x/other",
		Outcome:      "success",
		Method:       "GET",
		Path:         "/x/other",
		RoutePattern: "/x/other",
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

// regression: NormalizeEvent fills nil ID and zero CreatedAt; timestamps are UTC.
func TestNormalizeEvent_NilIDAndZeroCreatedAt(t *testing.T) {
	t.Parallel()
	ev := NormalizeEvent(Event{})
	if ev.EventID == uuid.Nil {
		t.Fatal("expected non-nil EventID")
	}
	if ev.CreatedAt.Location() != time.UTC {
		t.Fatalf("location = %v", ev.CreatedAt.Location())
	}
	fixed := time.Date(2024, 3, 1, 12, 0, 0, 0, time.FixedZone("EST", -5*3600))
	ev2 := NormalizeEvent(Event{CreatedAt: fixed})
	if ev2.CreatedAt.Location() != time.UTC {
		t.Fatalf("expected UTC normalization, got %v", ev2.CreatedAt.Location())
	}
}
