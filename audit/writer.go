package audit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Tx is the minimal pgx transaction surface WriteEntry needs. Any
// `pgx.Tx` satisfies it. Declared as an interface so tests can stub it
// without spinning up Postgres and so other packages can wrap a tx with
// instrumentation or metrics without forking WriteEntry.
type Tx interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Queryer is the minimal pgx.Conn / pgxpool.Pool surface VerifyChain
// needs. The audit-verify CLI plugs in a pool; tests can stub.
type Queryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// ChainViolation describes the first row whose recomputed hash does
// not match what's stored. Returned by VerifyChain so an oncall
// runbook can fetch the surrounding rows directly.
type ChainViolation struct {
	ID           int64
	ExpectedHash string
	GotHash      string
}

// auditChainRow is the minimum shape we need to recompute entry hashes
// row-by-row. Mirrors the column order in the qChain query below.
type auditChainRow struct {
	ID    int64
	Event Event
	Prev  string
	Stored string
}

// VerifyChain walks every audit_log row for orgID (or every row when
// orgID is nil), recomputes the entry hash from the stored fields +
// previous hash, and returns the first violation it sees. Returns
// (nil, nil) on a fully linear, untampered chain.
func VerifyChain(ctx context.Context, q Queryer, orgID *uuid.UUID) (*ChainViolation, error) {
	const qChain = `
		SELECT id, event_id, event_type, request_id, org_id, api_key_id,
		       actor_type, actor_id, resource_type, resource_id, action,
		       outcome, error_code, method, path, route_pattern, status_code,
		       ip_hmac, ip_org_ecies, token_fingerprint, prev_hash,
		       entry_hash, created_at
		FROM audit_log
		WHERE org_id IS NOT DISTINCT FROM $1
		ORDER BY id ASC`
	rows, err := q.Query(ctx, qChain, orgID)
	if err != nil {
		return nil, fmt.Errorf("audit: query chain: %w", err)
	}
	defer rows.Close()
	var lastHash string
	for rows.Next() {
		var (
			id              int64
			eventID         uuid.UUID
			eventType       string
			requestIDPtr    *string
			orgIDPtr        *uuid.UUID
			apiKeyIDPtr     *uuid.UUID
			actorType       string
			actorIDPtr      *string
			resourceTypePtr *string
			resourceIDPtr   *string
			actionPtr       *string
			outcome         string
			errorCodePtr    *string
			method          string
			path            string
			routePatternPtr *string
			statusCode      int
			ipHMAC          []byte
			ipOrgECIES      []byte
			tokenFPPtr      *string
			prevHashPtr     *string
			storedHash      string
			createdAt       time.Time
		)
		if err := rows.Scan(
			&id, &eventID, &eventType, &requestIDPtr, &orgIDPtr, &apiKeyIDPtr,
			&actorType, &actorIDPtr, &resourceTypePtr, &resourceIDPtr, &actionPtr,
			&outcome, &errorCodePtr, &method, &path, &routePatternPtr, &statusCode,
			&ipHMAC, &ipOrgECIES, &tokenFPPtr, &prevHashPtr,
			&storedHash, &createdAt,
		); err != nil {
			return nil, fmt.Errorf("audit: scan row: %w", err)
		}
		event := Event{
			EventID:          eventID,
			EventType:        eventType,
			RequestID:        derefString(requestIDPtr),
			OrgID:            orgIDPtr,
			APIKeyID:         apiKeyIDPtr,
			ActorType:        actorType,
			ActorID:          derefString(actorIDPtr),
			ResourceType:     derefString(resourceTypePtr),
			ResourceID:       derefString(resourceIDPtr),
			Action:           derefString(actionPtr),
			Outcome:          outcome,
			ErrorCode:        derefString(errorCodePtr),
			Method:           method,
			Path:             path,
			RoutePattern:     derefString(routePatternPtr),
			StatusCode:       statusCode,
			IPHMAC:           ipHMAC,
			IPOrgECIES:       ipOrgECIES,
			TokenFingerprint: derefString(tokenFPPtr),
			CreatedAt:        createdAt,
		}
		expectedPrev := lastHash
		if prevHashPtr != nil {
			// Trust the stored prev_hash for hashing — the chain
			// linkage check below catches a tampered prev.
			expectedPrev = *prevHashPtr
		}
		want := EntryHash(event, expectedPrev)
		if want != storedHash {
			return &ChainViolation{
				ID:           id,
				ExpectedHash: want,
				GotHash:      storedHash,
			}, nil
		}
		// Linkage: the row's prev_hash must equal the previous row's
		// entry_hash. The first row is allowed prev_hash NULL.
		if prevHashPtr == nil {
			if lastHash != "" {
				return &ChainViolation{
					ID:           id,
					ExpectedHash: lastHash,
					GotHash:      "",
				}, nil
			}
		} else if *prevHashPtr != lastHash {
			return &ChainViolation{
				ID:           id,
				ExpectedHash: lastHash,
				GotHash:      *prevHashPtr,
			}, nil
		}
		lastHash = storedHash
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: rows iter: %w", err)
	}
	return nil, nil
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// WriteEntry writes a chained audit row. Concurrent inserts for the same
// `org_id` are serialised by a Postgres transaction-scoped advisory lock on
// `hashtextextended(org_id::text, 0)` so both readers observe a single linear
// chain instead of reading the same `prev_hash` and forking it.
//
// Commit is the caller's responsibility. Returns the computed entry hash so
// the caller can log or ship it elsewhere.
//
// PII contract: see package doc — callers pass pre-redacted / HMAC'd /
// ECIES-encrypted fields on `Event`. WriteEntry does not inspect body content.
func WriteEntry(ctx context.Context, tx Tx, in Event) (string, error) {
	in = NormalizeEvent(in)
	if in.CreatedAt.IsZero() {
		in.CreatedAt = time.Now().UTC()
	}
	if in.EventID == uuid.Nil {
		in.EventID = uuid.New()
	}

	// Advisory lock key: `hashtextextended(org_id::text, 0)` when OrgID is
	// non-nil, the literal string "nil" otherwise (so system-level events
	// that have no org still share one queue). `pg_advisory_xact_lock`
	// releases automatically at commit/rollback — no manual unlock.
	orgKey := "nil"
	if in.OrgID != nil {
		orgKey = in.OrgID.String()
	}
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, orgKey); err != nil {
		return "", fmt.Errorf("audit: advisory lock: %w", err)
	}

	var prevHashPtr *string
	const qPrev = `SELECT entry_hash FROM audit_log
		WHERE org_id IS NOT DISTINCT FROM $1
		ORDER BY id DESC LIMIT 1`
	if err := tx.QueryRow(ctx, qPrev, in.OrgID).Scan(&prevHashPtr); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("audit: read prev hash: %w", err)
		}
		prevHashPtr = nil
	}

	prev := ""
	if prevHashPtr != nil {
		prev = *prevHashPtr
	}
	entryHash := EntryHash(in, prev)

	const qInsert = `
		INSERT INTO audit_log (
			event_id, event_type, request_id, org_id, api_key_id, actor_type, actor_id,
			resource_type, resource_id, action, outcome, error_code, method, path, route_pattern,
			status_code, ip_hmac, ip_org_ecies, token_fingerprint, prev_hash, entry_hash, created_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,
			$8,$9,$10,$11,$12,$13,$14,$15,
			$16,$17,$18,$19,$20,$21,$22
		)
	`
	if _, err := tx.Exec(
		ctx,
		qInsert,
		in.EventID,
		in.EventType,
		nilIfEmpty(in.RequestID),
		in.OrgID,
		in.APIKeyID,
		in.ActorType,
		nilIfEmpty(in.ActorID),
		nilIfEmpty(in.ResourceType),
		nilIfEmpty(in.ResourceID),
		nilIfEmpty(in.Action),
		in.Outcome,
		nilIfEmpty(in.ErrorCode),
		in.Method,
		in.Path,
		nilIfEmpty(in.RoutePattern),
		in.StatusCode,
		in.IPHMAC,
		in.IPOrgECIES,
		nilIfEmpty(in.TokenFingerprint),
		prevHashPtr,
		entryHash,
		in.CreatedAt.UTC(),
	); err != nil {
		return "", fmt.Errorf("audit: insert: %w", err)
	}
	return entryHash, nil
}
