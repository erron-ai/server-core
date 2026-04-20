package enclaveauth

import (
	"context"
	"errors"
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

func TestRefresh_ErrorSharedByAllWaiters(t *testing.T) {
	t.Parallel()
	want := errors.New("bootstrap failed")
	var rb Rebootstrapper
	fn := func(ctx context.Context) (string, error) {
		return "", want
	}
	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := rb.Refresh(context.Background(), fn)
			if !errors.Is(err, want) {
				t.Errorf("got %v", err)
			}
		}()
	}
	wg.Wait()
}

// regression: second caller with canceled context still receives singleflight result
// from the first (stdlib singleflight behavior).
func TestRefresh_CanceledSecondCallerStillGetsResult(t *testing.T) {
	t.Parallel()
	var rb Rebootstrapper
	var calls int32
	fn := func(ctx context.Context) (string, error) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(40 * time.Millisecond)
		return "ok", nil
	}
	ctx1 := context.Background()
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()

	var wg sync.WaitGroup
	wg.Add(2)
	var err1, err2 error
	go func() {
		defer wg.Done()
		_, err1 = rb.Refresh(ctx1, fn)
	}()
	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		_, err2 = rb.Refresh(ctx2, fn)
	}()
	wg.Wait()
	if err1 != nil || err2 != nil {
		t.Fatalf("err1=%v err2=%v", err1, err2)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("calls = %d", calls)
	}
}
