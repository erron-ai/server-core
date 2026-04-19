package ratelimit

import (
	"context"
	"errors"
	"time"
)

// RedisLike is the minimal slice of go-redis we depend on. Products
// adapt their concrete client. Returning a typed error instead of an
// int when the call fails forces fail-closed handling at call sites.
type RedisLike interface {
	IncrementExpiringCounter(ctx context.Context, key string, ttl time.Duration) (int, error)
	Delete(ctx context.Context, key string) error
}

// ErrNoRedis is returned by IncrementExpiringCounter when Redis is
// expected (rdb non-nil) but unreachable. Callers MUST treat this as
// a fail-closed signal — degrading to an in-memory counter would
// silently break the shared cap across replicas.
var ErrNoRedis = errors.New("ratelimit: redis unavailable")

// IncrementExpiringCounter is a thin proxy over RedisLike that exists
// so consumers can wrap it in their own metrics/log layer.
func IncrementExpiringCounter(ctx context.Context, rdb RedisLike, key string, ttl time.Duration) (int, error) {
	if rdb == nil {
		return 0, ErrNoRedis
	}
	return rdb.IncrementExpiringCounter(ctx, key, ttl)
}
