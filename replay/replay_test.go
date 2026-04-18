package replay

import (
	"encoding/json"
	"testing"
)

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

func TestClassifyExistingNoStateAndEmptyRequest(t *testing.T) {
	// No stored fingerprint at all — caller has nothing cached.
	if got := ClassifyExisting(nil, nil, 0, nil); got.Outcome != OutcomeNoState {
		t.Fatalf("expected no_state with empty stored fp, got %s", got.Outcome)
	}
	// Stored row but empty request fingerprint (pre-launch edge case) —
	// conflict SHOULD NOT fire because we have nothing to compare against;
	// fall through to the cached/in-flight classification based on stored body.
	stored := FingerprintBody([]byte(`{"hello":"world"}`))
	got := ClassifyExisting(nil, stored, 200, []byte(`{"ok":true}`))
	if got.Outcome != OutcomeCached {
		t.Fatalf("expected cached with empty req fp, got %s", got.Outcome)
	}
}
