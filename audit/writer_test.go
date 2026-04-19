//go:build integration

package audit

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestWriteEntry_ConcurrentInsertsStayLinear fires N goroutines inserting for
// the same org and asserts that the resulting chain has no forks: every row's
// `prev_hash` matches the preceding row's `entry_hash` and no `prev_hash`
// value is duplicated. Run under `go test -race -tags=integration` with
// `PG_TEST_DSN` pointing at a scratch database.
//
// The test uses the real WriteEntry path, so it exercises the advisory lock
// AND the `UNIQUE(org_id, prev_hash)` schema guard together.
func TestWriteEntry_ConcurrentInsertsStayLinear(t *testing.T) {
	dsn := os.Getenv("PG_TEST_DSN")
	if dsn == "" {
		t.Skip("set PG_TEST_DSN=postgres://... to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	if err := ensureSchema(ctx, pool); err != nil {
		t.Fatalf("schema: %v", err)
	}

	orgID := uuid.New()
	_, _ = pool.Exec(ctx, `DELETE FROM audit_log WHERE org_id = $1`, orgID)

	const workers = 50
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, err := pool.Begin(ctx)
			if err != nil {
				errCh <- err
				return
			}
			if _, err := WriteEntry(ctx, tx, Event{
				EventID:    uuid.New(),
				EventType:  "test.concurrent",
				OrgID:      &orgID,
				ActorType:  "system",
				Outcome:    "success",
				Method:     "POST",
				Path:       "/test",
				StatusCode: 200,
				CreatedAt:  time.Now().UTC(),
			}); err != nil {
				_ = tx.Rollback(ctx)
				errCh <- err
				return
			}
			if err := tx.Commit(ctx); err != nil {
				errCh <- err
				return
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("insert: %v", err)
	}

	rows, err := pool.Query(ctx,
		`SELECT prev_hash, entry_hash FROM audit_log WHERE org_id = $1 ORDER BY id ASC`, orgID)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	defer rows.Close()

	var prev string
	seenPrev := map[string]struct{}{}
	count := 0
	first := true
	for rows.Next() {
		var got, entry *string
		if err := rows.Scan(&got, &entry); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if first {
			if got != nil {
				t.Fatalf("first row prev_hash should be NULL, got %q", *got)
			}
			if entry == nil {
				t.Fatal("first row entry_hash is NULL")
			}
			prev = *entry
			first = false
			count++
			continue
		}
		if got == nil {
			t.Fatal("non-first row must have prev_hash")
		}
		if *got != prev {
			t.Fatalf("chain fork at row %d: prev_hash %q != previous entry_hash %q",
				count, *got, prev)
		}
		if _, dup := seenPrev[*got]; dup {
			t.Fatalf("duplicate prev_hash %q — fork not serialised", *got)
		}
		seenPrev[*got] = struct{}{}
		if entry == nil {
			t.Fatal("entry_hash is NULL")
		}
		prev = *entry
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows err: %v", err)
	}
	if count != workers {
		t.Fatalf("want %d rows, got %d", workers, count)
	}
}

func ensureSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS audit_log (
		id                BIGSERIAL PRIMARY KEY,
		event_id          UUID NOT NULL DEFAULT gen_random_uuid(),
		event_type        TEXT NOT NULL DEFAULT 'http.request',
		request_id        TEXT,
		org_id            UUID,
		api_key_id        UUID,
		actor_type        TEXT NOT NULL DEFAULT 'unknown',
		actor_id          TEXT,
		resource_type     TEXT,
		resource_id       TEXT,
		action            TEXT,
		outcome           TEXT NOT NULL DEFAULT 'unknown',
		error_code        TEXT,
		method            TEXT NOT NULL DEFAULT '',
		path              TEXT NOT NULL DEFAULT '',
		route_pattern     TEXT,
		status_code       INTEGER NOT NULL DEFAULT 0,
		ip_hmac           BYTEA,
		ip_org_ecies      BYTEA,
		token_fingerprint TEXT,
		prev_hash         TEXT,
		entry_hash        TEXT,
		created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
		UNIQUE (org_id, prev_hash)
	)`)
	return err
}

// Verify pgx.Tx satisfies the writer's Tx interface at compile time.
var _ Tx = (pgx.Tx)(nil)
