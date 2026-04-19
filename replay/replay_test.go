package replay

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestAttemptCounter_memoryPath(t *testing.T) {
	t.Parallel()
	key := "attempt:" + t.Name()
	ctx := context.Background()
	c1, blocked, err := AttemptCounter(ctx, nil, key, time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	if c1 != 1 || blocked {
		t.Fatalf("got count=%d blocked=%v", c1, blocked)
	}
	c2, blocked, err := AttemptCounter(ctx, nil, key, time.Minute, 2)
	if err != nil {
		t.Fatal(err)
	}
	if c2 != 2 || blocked {
		t.Fatalf("got count=%d blocked=%v", c2, blocked)
	}
	c3, blocked, err := AttemptCounter(ctx, nil, key, time.Minute, 2)
	if err != nil {
		t.Fatal(err)
	}
	if c3 != 3 || !blocked {
		t.Fatalf("got count=%d blocked=%v want blocked", c3, blocked)
	}
	if err := Reset(ctx, nil, key); err != nil {
		t.Fatal(err)
	}
	after, _, err := AttemptCounter(ctx, nil, key, time.Minute, 0)
	if err != nil || after != 1 {
		t.Fatalf("after reset count=%d err=%v", after, err)
	}
}

func TestFingerprintBodyDeterministic(t *testing.T) {
	first := FingerprintBody([]byte(`{"hello":"world"}`))
	second := FingerprintBody([]byte(`{"hello":"world"}`))
	if string(first) != string(second) {
		t.Fatal("fingerprints should be deterministic")
	}
}

func TestClassifyExistingCached(t *testing.T) {
	fingerprint := FingerprintBody([]byte(`{"hello":"world"}`))
	decision := ClassifyExisting(fingerprint, fingerprint, 200, []byte(`{"ok":true}`))
	if decision.Outcome != OutcomeCached {
		t.Fatalf("expected cached outcome, got %s", decision.Outcome)
	}
	var body map[string]bool
	if err := json.Unmarshal(decision.Body, &body); err != nil {
		t.Fatalf("unmarshal cached body: %v", err)
	}
}

func TestClassifyExistingConflict(t *testing.T) {
	first := FingerprintBody([]byte(`{"hello":"world"}`))
	second := FingerprintBody([]byte(`{"goodbye":"world"}`))
	decision := ClassifyExisting(first, second, 0, nil)
	if decision.Outcome != OutcomeConflict {
		t.Fatalf("expected conflict outcome, got %s", decision.Outcome)
	}
}

func TestClassifyExistingInFlight(t *testing.T) {
	fingerprint := FingerprintBody([]byte(`{"hello":"world"}`))
	decision := ClassifyExisting(fingerprint, fingerprint, 0, nil)
	if decision.Outcome != OutcomeInFlight {
		t.Fatalf("expected in flight outcome, got %s", decision.Outcome)
	}
}

// TestClassifyExisting_Edge is the D4 exit-criterion table test named by
// plan §5.1: it covers the (empty-req-fp × nil-body × present-stored-fp)
// corner and the "no stored state at all" corner, matching the HTTP
// behaviour the server presents to idempotency callers.
func TestClassifyExisting_Edge(t *testing.T) {
	stored := FingerprintBody([]byte(`{"hello":"world"}`))

	cases := []struct {
		name         string
		requestFP    []byte
		storedFP     []byte
		storedStatus int
		storedBody   []byte
		want         Outcome
	}{
		{"no_state: empty stored fp", nil, nil, 0, nil, OutcomeNoState},
		{"cached: empty req fp × present stored fp × body", nil, stored, 200, []byte(`{"ok":true}`), OutcomeCached},
		{"in_flight: empty req fp × present stored fp × nil body", nil, stored, 0, nil, OutcomeInFlight},
		{"in_flight: matching fps × nil body", stored, stored, 0, nil, OutcomeInFlight},
		{"cached: matching fps × present body", stored, stored, 200, []byte(`{"ok":true}`), OutcomeCached},
		{"conflict: mismatched fps", FingerprintBody([]byte(`{"a":1}`)), stored, 0, nil, OutcomeConflict},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyExisting(tc.requestFP, tc.storedFP, tc.storedStatus, tc.storedBody)
			if got.Outcome != tc.want {
				t.Fatalf("ClassifyExisting = %s, want %s", got.Outcome, tc.want)
			}
		})
	}
}
