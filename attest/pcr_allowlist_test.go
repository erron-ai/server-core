package attest

import (
	"strings"
	"testing"
)

func TestParsePCRAllowlistJSON_EmptyReturnsNilSlice(t *testing.T) {
	t.Parallel()
	got, err := ParsePCRAllowlistJSON("")
	if err != nil {
		t.Fatalf("ParsePCRAllowlistJSON: %v", err)
	}
	if got != nil {
		t.Fatalf("want nil slice, got %#v", got)
	}
}

func TestParsePCRAllowlistJSON_InvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := ParsePCRAllowlistJSON(`not-json`)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParsePCRAllowlistJSON_InvalidPCRIndex(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  string
	}{
		{name: "negative", raw: `[{"-1":"aa"}]`},
		{name: "too_large", raw: `[{"32":"aa"}]`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParsePCRAllowlistJSON(tc.raw)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), "invalid pcr index") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParsePCRAllowlistJSON_InvalidHex(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  string
	}{
		{name: "odd_length", raw: `[{"0":"aab"}]`},
		{name: "non_hex", raw: `[{"0":"xyz"}]`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParsePCRAllowlistJSON(tc.raw)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParsePCRAllowlistJSON_EmptyInnerMap(t *testing.T) {
	t.Parallel()
	_, err := ParsePCRAllowlistJSON(`[{}]`)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "empty pcr set in allowlist") {
		t.Fatalf("unexpected error: %v", err)
	}
}
