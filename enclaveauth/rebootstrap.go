// Package enclaveauth provides shared concurrency primitives for the
// Go server's enclave bootstrap path. The Rebootstrapper collapses
// concurrent stale-key 401s into a single ECDH handshake — without it,
// N goroutines that observe a 401 simultaneously each run the full
// bootstrap, multiplying enclave-side work and burning vsock retries.
//
// PII contract: opaque input — handlers fetch a fresh request-auth key
// hex string. No PII enters this package.
package enclaveauth

import (
	"context"

	"golang.org/x/sync/singleflight"
)

// Rebootstrapper deduplicates concurrent calls to a slow bootstrap fn.
// Zero value is ready to use.
type Rebootstrapper struct {
	sf singleflight.Group
}

// Refresh collapses concurrent callers onto a single in-flight
// invocation of fn. All waiters receive the same (string, error)
// result. There is no timed cache — once fn returns, the next call
// starts a fresh flight. This matches the bcrypt singleflight pattern
// used by the product's auth middleware and avoids the stale-key race
// of any cache TTL.
func (r *Rebootstrapper) Refresh(ctx context.Context, fn func(context.Context) (string, error)) (string, error) {
	v, err, _ := r.sf.Do("rebootstrap", func() (any, error) {
		return fn(ctx)
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}
