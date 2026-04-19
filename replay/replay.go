// Package replay implements idempotency fingerprinting and stored-row
// classification used across all server-core-consuming products. Any verb
// that needs idempotent first-seen semantics plugs into this package — it is
// explicitly product-neutral.
//
// PII contract: ciphertext/identifier-only input. The fingerprinted body MUST
// contain only SDK-produced ciphertext plus identifier hashes. Callers MUST
// reject plaintext PII fields in the request BEFORE fingerprinting (see
// plan §6.1 transit plaintext-rejection gate for the Mail gate).
package replay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"
)

// Outcome is the classification result of an idempotency-cache lookup.
type Outcome string

const (
	OutcomeFirstClaim Outcome = "first_claim"
	OutcomeCached     Outcome = "cached"
	OutcomeConflict   Outcome = "conflict"
	OutcomeInFlight   Outcome = "in_flight"
	OutcomeNoState    Outcome = "no_state"
)

// Decision is the caller-facing result of ClassifyExisting.
type Decision struct {
	Outcome Outcome
	Status  int
	Body    json.RawMessage
}

// FingerprintBody returns SHA-256(raw). The bytes SHOULD be the canonical
// request body; callers MUST gate plaintext PII rejection upstream.
//
// PII contract: ciphertext/identifier-only input. See package doc.
func FingerprintBody(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return sum[:]
}

// RedisLike is the minimal Redis client surface AttemptCounter
// requires. Match the product's existing redisx.Client interface so a
// type assertion is unnecessary.
type RedisLike interface {
	IncrementExpiringCounter(ctx context.Context, key string, ttl time.Duration) (int, error)
	Delete(ctx context.Context, key string) error
}

// AttemptCounter increments a Redis-first counter with a sliding TTL
// and returns (count, blocked). When `rdb` is nil the function falls
// back to an in-process counter so dev/test environments without
// Redis still get deterministic behaviour. When `rdb` is non-nil and
// unreachable, the error is propagated — callers MUST fail closed.
//
// `blocked` is true iff count > max. The 0-value max disables the
// block decision (count is still returned).
func AttemptCounter(ctx context.Context, rdb RedisLike, key string, ttl time.Duration, max int) (count int, blocked bool, err error) {
	if rdb != nil {
		c, err := rdb.IncrementExpiringCounter(ctx, key, ttl)
		if err != nil {
			return 0, false, err
		}
		return c, max > 0 && c > max, nil
	}
	c := memoryCounters.increment(key, ttl)
	return c, max > 0 && c > max, nil
}

// Reset clears the per-key counter after a successful operation.
// When `rdb` is nil this clears the in-process counter.
func Reset(ctx context.Context, rdb RedisLike, key string) error {
	if rdb != nil {
		return rdb.Delete(ctx, key)
	}
	memoryCounters.reset(key)
	return nil
}

type memoryCounter struct {
	count    int
	expireAt time.Time
}

type memoryCounterStore struct {
	mu sync.Mutex
	m  map[string]*memoryCounter
}

func (s *memoryCounterStore) increment(key string, ttl time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]*memoryCounter{}
	}
	now := time.Now()
	c, ok := s.m[key]
	if !ok || (!c.expireAt.IsZero() && now.After(c.expireAt)) {
		c = &memoryCounter{}
		s.m[key] = c
	}
	c.count++
	if ttl > 0 {
		c.expireAt = now.Add(ttl)
	}
	return c.count
}

func (s *memoryCounterStore) reset(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
}

var memoryCounters = &memoryCounterStore{}

// ClassifyExisting compares the in-flight fingerprint against the stored row
// and returns the idempotency decision for the handler to act on.
func ClassifyExisting(requestFingerprint, storedFingerprint []byte, storedStatus int, storedBody []byte) Decision {
	if len(storedFingerprint) == 0 {
		return Decision{Outcome: OutcomeNoState}
	}
	if len(requestFingerprint) > 0 && !bytes.Equal(storedFingerprint, requestFingerprint) {
		return Decision{Outcome: OutcomeConflict}
	}
	if len(storedBody) > 0 {
		return Decision{
			Outcome: OutcomeCached,
			Status:  storedStatus,
			Body:    json.RawMessage(storedBody),
		}
	}
	return Decision{Outcome: OutcomeInFlight}
}
