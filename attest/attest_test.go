package attest

import (
	"encoding/base64"
	"testing"
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
