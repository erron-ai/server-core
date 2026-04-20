package main

import (
	"testing"
)

func TestRun_MissingDSN(t *testing.T) {
	t.Parallel()
	if got := run(nil); got != 2 {
		t.Fatalf("exit = %d", got)
	}
}

func TestRun_InvalidOrgUUID(t *testing.T) {
	t.Parallel()
	if got := run([]string{"--dsn", "postgres://x", "--org", "not-a-uuid"}); got != 2 {
		t.Fatalf("exit = %d", got)
	}
}

func TestRun_DBConnectFailure(t *testing.T) {
	t.Parallel()
	if got := run([]string{"--dsn", "postgres://127.0.0.1:9/nope"}); got != 1 {
		t.Fatalf("exit = %d", got)
	}
}
