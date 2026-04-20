package audit

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type chainRowFixture struct {
	ID     int64
	Event  Event
	Prev   string
	Stored string
}

type fakeChainRows struct {
	rows []chainRowFixture
	i    int
	err  error
}

func (f *fakeChainRows) Close() {}

func (f *fakeChainRows) Err() error {
	return f.err
}

func (f *fakeChainRows) CommandTag() pgconn.CommandTag { return pgconn.CommandTag{} }

func (f *fakeChainRows) FieldDescriptions() []pgconn.FieldDescription { return nil }

func (f *fakeChainRows) Next() bool {
	if f.err != nil {
		return false
	}
	return f.i < len(f.rows)
}

func (f *fakeChainRows) Scan(dest ...any) error {
	r := f.rows[f.i]
	f.i++
	e := r.Event

	var requestIDPtr *string
	if e.RequestID != "" {
		s := e.RequestID
		requestIDPtr = &s
	}
	var actorIDPtr, resourceTypePtr, resourceIDPtr, actionPtr, errorCodePtr, routePatternPtr, tokenFPPtr *string
	if e.ActorID != "" {
		s := e.ActorID
		actorIDPtr = &s
	}
	if e.ResourceType != "" {
		s := e.ResourceType
		resourceTypePtr = &s
	}
	if e.ResourceID != "" {
		s := e.ResourceID
		resourceIDPtr = &s
	}
	if e.Action != "" {
		s := e.Action
		actionPtr = &s
	}
	if e.ErrorCode != "" {
		s := e.ErrorCode
		errorCodePtr = &s
	}
	if e.RoutePattern != "" {
		s := e.RoutePattern
		routePatternPtr = &s
	}
	if e.TokenFingerprint != "" {
		s := e.TokenFingerprint
		tokenFPPtr = &s
	}
	var prevPtr *string
	if r.Prev != "" {
		s := r.Prev
		prevPtr = &s
	}

	*(dest[0].(*int64)) = r.ID
	*(dest[1].(*uuid.UUID)) = e.EventID
	*(dest[2].(*string)) = e.EventType
	*(dest[3].(**string)) = requestIDPtr
	*(dest[4].(**uuid.UUID)) = e.OrgID
	*(dest[5].(**uuid.UUID)) = e.APIKeyID
	*(dest[6].(*string)) = e.ActorType
	*(dest[7].(**string)) = actorIDPtr
	*(dest[8].(**string)) = resourceTypePtr
	*(dest[9].(**string)) = resourceIDPtr
	*(dest[10].(**string)) = actionPtr
	*(dest[11].(*string)) = e.Outcome
	*(dest[12].(**string)) = errorCodePtr
	*(dest[13].(*string)) = e.Method
	*(dest[14].(*string)) = e.Path
	*(dest[15].(**string)) = routePatternPtr
	sc := e.StatusCode
	*(dest[16].(*int)) = sc
	*(dest[17].(*[]byte)) = e.IPHMAC
	*(dest[18].(*[]byte)) = e.IPOrgECIES
	*(dest[19].(**string)) = tokenFPPtr
	*(dest[20].(**string)) = prevPtr
	*(dest[21].(*string)) = r.Stored
	*(dest[22].(*time.Time)) = e.CreatedAt
	return nil
}

func (f *fakeChainRows) Values() ([]any, error) {
	panic("not used")
}

func (f *fakeChainRows) RawValues() [][]byte {
	panic("not used")
}

func (f *fakeChainRows) Conn() *pgx.Conn {
	return nil
}

type fakeChainQueryer struct {
	rows pgx.Rows
}

func (f *fakeChainQueryer) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return f.rows, nil
}

func TestVerifyChain_EmptyRowsReturnsNil(t *testing.T) {
	t.Parallel()
	q := &fakeChainQueryer{rows: &fakeChainRows{}}
	v, err := VerifyChain(context.Background(), q, nil)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if v != nil {
		t.Fatalf("expected nil violation, got %+v", v)
	}
}

func TestVerifyChain_FirstRowNonNilPrevHashIsViolation(t *testing.T) {
	t.Parallel()
	org := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	ev := Event{
		EventID:   uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		EventType: "http.request",
		Method:    "GET",
		Path:      "/x",
		Outcome:   "success",
		CreatedAt: time.Unix(1700000000, 0).UTC(),
		OrgID:     &org,
	}
	prev := "should-not-be-set-on-first"
	hash := EntryHash(ev, prev)
	row := chainRowFixture{
		Event:  ev,
		Prev:   prev,
		Stored: hash,
		ID:     1,
	}
	q := &fakeChainQueryer{rows: &fakeChainRows{rows: []chainRowFixture{row}}}
	v, err := VerifyChain(context.Background(), q, &org)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if v == nil {
		t.Fatal("expected linkage violation")
	}
	if v.GotHash != prev {
		t.Fatalf("GotHash = %q, want %q", v.GotHash, prev)
	}
}

func TestVerifyChain_TamperedEntryHashIsViolation(t *testing.T) {
	t.Parallel()
	org := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	ev := Event{
		EventID:   uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		EventType: "http.request",
		Method:    "GET",
		Path:      "/x",
		Outcome:   "success",
		CreatedAt: time.Unix(1700000000, 0).UTC(),
		OrgID:     &org,
	}
	want := EntryHash(ev, "")
	row := chainRowFixture{
		Event:  ev,
		Prev:   "",
		Stored: "deadbeef" + want[8:],
		ID:     1,
	}
	q := &fakeChainQueryer{rows: &fakeChainRows{rows: []chainRowFixture{row}}}
	v, err := VerifyChain(context.Background(), q, &org)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if v == nil {
		t.Fatal("expected hash violation")
	}
	if v.ExpectedHash != want {
		t.Fatalf("ExpectedHash mismatch")
	}
}
