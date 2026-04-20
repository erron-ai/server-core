package attest

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	coreerrors "github.com/erron-ai/server-core/errors"
)

func TestParseChallengeRequest_Valid(t *testing.T) {
	raw := []byte(`{"challenge":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}`)

	req, decoded, err := ParseChallengeRequest(raw)
	if err != nil {
		t.Fatalf("ParseChallengeRequest() error = %v", err)
	}
	if req.Challenge == "" {
		t.Fatal("expected challenge to be preserved")
	}
	if len(decoded) != 32 {
		t.Fatalf("decoded challenge len = %d, want 32", len(decoded))
	}
}

func TestParseChallengeRequest_DecodesMinimum32Bytes(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"challenge":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}`)
	_, decoded, err := ParseChallengeRequest(raw)
	if err != nil {
		t.Fatalf("ParseChallengeRequest: %v", err)
	}
	if len(decoded) < MinChallengeBytes {
		t.Fatalf("len(decoded) = %d", len(decoded))
	}
}

func TestParseChallengeRequest_RejectsBase64DecodingTo31Bytes(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"challenge":"` + base64.StdEncoding.EncodeToString(make([]byte, 31)) + `"}`)
	_, _, err := ParseChallengeRequest(raw)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseChallengeRequest_RejectsUTF8LengthOver512(t *testing.T) {
	t.Parallel()
	// Encoded challenge string length > 512 UTF-8 bytes (ASCII repeats — valid JSON string).
	long := strings.Repeat("A", 513)
	raw := []byte(`{"challenge":"` + long + `"}`)
	_, _, err := ParseChallengeRequest(raw)
	if err == nil {
		t.Fatal("expected error")
	}
	if coreerrors.CodeOf(err) != string(coreerrors.CodeInvalidField) {
		t.Fatalf("code = %q", coreerrors.CodeOf(err))
	}
}

func TestParseChallengeRequest_IgnoresExtraJSONFields(t *testing.T) {
	t.Parallel()
	ch := base64.StdEncoding.EncodeToString(make([]byte, 32))
	raw, err := json.Marshal(map[string]string{
		"challenge": ch,
		"extra":     "ignored",
	})
	if err != nil {
		t.Fatal(err)
	}
	req, _, err := ParseChallengeRequest(raw)
	if err != nil {
		t.Fatalf("ParseChallengeRequest: %v", err)
	}
	if req.Challenge != ch {
		t.Fatalf("challenge = %q", req.Challenge)
	}
}

// regression: JSON string may include surrounding spaces; TrimSpace on the
// challenge accepts valid base64 after trim.
func TestParseChallengeRequest_WhitespaceAroundChallenge_TrimsAndAccepts(t *testing.T) {
	t.Parallel()
	ch := base64.StdEncoding.EncodeToString(make([]byte, 32))
	raw := []byte(`{"challenge":" ` + ch + ` "}`)
	req, decoded, err := ParseChallengeRequest(raw)
	if err != nil {
		t.Fatalf("ParseChallengeRequest: %v", err)
	}
	if req.Challenge != ch {
		t.Fatalf("challenge not trimmed: %q", req.Challenge)
	}
	if len(decoded) < MinChallengeBytes {
		t.Fatalf("len = %d", len(decoded))
	}
}

func TestParseChallengeRequest_InvalidCases(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{
			name: "invalid json",
			raw:  []byte(`{"challenge"`),
		},
		{
			name: "missing challenge",
			raw:  []byte(`{"challenge":"   "}`),
		},
		{
			name: "too long encoded challenge",
			raw:  []byte(`{"challenge":"` + string(make([]byte, 513)) + `"}`),
		},
		{
			name: "invalid base64",
			raw:  []byte(`{"challenge":"***"}`),
		},
		{
			name: "too short decoded",
			raw:  []byte(`{"challenge":"` + base64.StdEncoding.EncodeToString(make([]byte, 31)) + `"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := ParseChallengeRequest(tt.raw); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
