// audit-verify walks the audit_log chain for an org (or every org)
// and exits non-zero on the first tampered or out-of-order row.
//
// Intended for nightly cron in production: a violation pages oncall.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dorsalmail/server-core/audit"
)

func main() {
	dsn := flag.String("dsn", "", "Postgres DSN (required)")
	orgFlag := flag.String("org", "", "single org UUID to verify (default: every org)")
	emitJSON := flag.Bool("json", false, "emit per-chain results as JSON")
	timeout := flag.Duration("timeout", 5*time.Minute, "context timeout for the verify run")
	flag.Parse()

	if *dsn == "" {
		fmt.Fprintln(os.Stderr, "usage: audit-verify --dsn postgres://... [--org UUID] [--json]")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit-verify: connect: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	var orgs []*uuid.UUID
	if *orgFlag != "" {
		id, err := uuid.Parse(*orgFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "audit-verify: bad --org: %v\n", err)
			os.Exit(2)
		}
		orgs = append(orgs, &id)
	} else {
		orgs, err = listOrgs(ctx, pool)
		if err != nil {
			fmt.Fprintf(os.Stderr, "audit-verify: list orgs: %v\n", err)
			os.Exit(1)
		}
	}

	hadViolation := false
	enc := json.NewEncoder(os.Stdout)
	for _, org := range orgs {
		v, err := audit.VerifyChain(ctx, pool, org)
		if err != nil {
			fmt.Fprintf(os.Stderr, "audit-verify: %v: %v\n", orgString(org), err)
			os.Exit(1)
		}
		report := map[string]any{
			"org":   orgString(org),
			"clean": v == nil,
		}
		if v != nil {
			hadViolation = true
			report["violation"] = v
		}
		if *emitJSON {
			_ = enc.Encode(report)
		} else if v != nil {
			fmt.Fprintf(os.Stderr, "VIOLATION org=%s id=%d expected=%s got=%s\n",
				orgString(org), v.ID, v.ExpectedHash, v.GotHash)
		}
	}
	if hadViolation {
		os.Exit(1)
	}
}

func listOrgs(ctx context.Context, pool *pgxpool.Pool) ([]*uuid.UUID, error) {
	const q = `SELECT DISTINCT org_id FROM audit_log`
	rows, err := pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*uuid.UUID
	for rows.Next() {
		var id *uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func orgString(p *uuid.UUID) string {
	if p == nil {
		return "<nil>"
	}
	return p.String()
}
