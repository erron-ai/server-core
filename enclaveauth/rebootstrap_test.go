package enclaveauth

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRefreshDeduplicatesConcurrentCalls(t *testing.T) {
	var calls int32
	var rb Rebootstrapper
	fn := func(ctx context.Context) (string, error) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(50 * time.Millisecond)
		return "shared-key", nil
	}
	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	results := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			v, err := rb.Refresh(context.Background(), fn)
			results[i] = v
			errs[i] = err
		}(i)
	}
	wg.Wait()
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected exactly 1 fn call, got %d", got)
	}
	for i, v := range results {
		if errs[i] != nil {
			t.Fatalf("waiter %d got err: %v", i, errs[i])
		}
		if v != "shared-key" {
			t.Fatalf("waiter %d got %q, want shared-key", i, v)
		}
	}
}

func TestRefreshAllowsNewFlightAfterCompletion(t *testing.T) {
	var calls int32
	var rb Rebootstrapper
	fn := func(ctx context.Context) (string, error) {
		atomic.AddInt32(&calls, 1)
		return "k", nil
	}
	if _, err := rb.Refresh(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
	if _, err := rb.Refresh(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("want 2 sequential calls, got %d", got)
	}
}
