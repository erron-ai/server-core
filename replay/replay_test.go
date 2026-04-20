package replay

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
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

type stubRedis struct {
	mu    sync.Mutex
	count int
	err   error
}

func (s *stubRedis) IncrementExpiringCounter(ctx context.Context, key string, ttl time.Duration) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
	return s.count, nil
}

func (s *stubRedis) Delete(ctx context.Context, key string) error {
	return nil
}

func TestAttemptCounter_RedisStubIncrements(t *testing.T) {
	t.Parallel()
	rdb := &stubRedis{}
	ctx := context.Background()
	for want := 1; want <= 3; want++ {
		got, blocked, err := AttemptCounter(ctx, rdb, "k", time.Minute, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got != want || blocked {
			t.Fatalf("want count=%d blocked=false, got count=%d blocked=%v", want, got, blocked)
		}
	}
}

func TestAttemptCounter_MaxZeroNeverBlocks(t *testing.T) {
	t.Parallel()
	rdb := &stubRedis{}
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, blocked, err := AttemptCounter(ctx, rdb, "k", time.Minute, 0)
		if err != nil {
			t.Fatal(err)
		}
		if blocked {
			t.Fatal("max=0 must never block")
		}
	}
}

func TestAttemptCounter_BlockedWhenCountExceedsMax(t *testing.T) {
	t.Parallel()
	rdb := &stubRedis{}
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		count, blocked, err := AttemptCounter(ctx, rdb, "k", time.Minute, 2)
		if err != nil {
			t.Fatal(err)
		}
		switch i {
		case 1, 2:
			if blocked {
				t.Fatalf("step %d: unexpected block", i)
			}
		case 3:
			if !blocked {
				t.Fatal("step 3: expected blocked when count > max")
			}
		}
		if count != i {
			t.Fatalf("count = %d, want %d", count, i)
		}
	}
}

func TestAttemptCounter_RedisErrorPropagates(t *testing.T) {
	t.Parallel()
	want := errors.New("redis down")
	rdb := &stubRedis{err: want}
	_, _, err := AttemptCounter(context.Background(), rdb, "k", time.Minute, 1)
	if !errors.Is(err, want) {
		t.Fatalf("got %v", err)
	}
}

func TestAttemptCounter_ConcurrentSameKeyMemoryPath(t *testing.T) {
	t.Parallel()
	const n = 50
	key := "conc:" + t.Name()
	var wg sync.WaitGroup
	var final int32
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			c, _, err := AttemptCounter(context.Background(), nil, key, time.Minute, 0)
			if err != nil {
				panic(err)
			}
			atomic.StoreInt32(&final, int32(c))
		}()
	}
	wg.Wait()
	if final != n {
		t.Fatalf("final count = %d, want %d", final, n)
	}
}

func TestClassifyExisting_NoStoredFingerprint_OutcomeNoState(t *testing.T) {
	t.Parallel()
	fp := FingerprintBody([]byte(`{}`))
	d := ClassifyExisting(fp, nil, 0, nil)
	if d.Outcome != OutcomeNoState {
		t.Fatalf("got %s", d.Outcome)
	}
}

func TestClassifyExisting_EmptyRequestFP_NoConflict(t *testing.T) {
	t.Parallel()
	stored := FingerprintBody([]byte(`{"a":1}`))
	d := ClassifyExisting(nil, stored, 0, nil)
	if d.Outcome == OutcomeConflict {
		t.Fatal("empty request FP must not be classified as conflict")
	}
}

func TestAttemptCounter_TTLZeroPersistsUntilReset(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key := "ttl0:" + t.Name()
	c1, _, _ := AttemptCounter(ctx, nil, key, 0, 0)
	if c1 != 1 {
		t.Fatalf("count = %d", c1)
	}
	c2, _, _ := AttemptCounter(ctx, nil, key, 0, 0)
	if c2 != 2 {
		t.Fatalf("ttl=0 must not expire between calls: got %d", c2)
	}
	if err := Reset(ctx, nil, key); err != nil {
		t.Fatal(err)
	}
	c3, _, _ := AttemptCounter(ctx, nil, key, 0, 0)
	if c3 != 1 {
		t.Fatalf("after reset want 1, got %d", c3)
	}
}
