package vectors

import (
	"github.com/google/uuid"

	coreaudit "github.com/dorsalmail/server-core/audit"
)

type CanonicalRequestVector struct {
	Name      string
	Product   string
	Method    string
	Path      string
	Timestamp int64
	Nonce     string
	Body      []byte
	Canonical string
}

type ReplayVector struct {
	Name          string
	RequestBody   []byte
	StoredBody    []byte
	StoredStatus  int
	Conflict      bool
	Cached        bool
	ExpectedState string
}

type AuditVector struct {
	Name         string
	InputPath    string
	Redacted     string
	Event        coreaudit.Event
	PrevHash     string
	ExpectedHash string
}

type TransitHashVector struct {
	Name      string
	MasterHex string
	OrgID     uuid.UUID
	Principal string
}

var CanonicalRequestVectors = []CanonicalRequestVector{
	{
		Name:      "basic-post-dorsalmail",
		Product:   "dorsalmail",
		Method:    "POST",
		Path:      "/transit",
		Timestamp: 1700000000,
		Nonce:     "00112233445566778899aabb",
		Body:      []byte(`{"hello":"world"}`),
		Canonical: "dorsalmail\nPOST\n/transit\n1700000000\n00112233445566778899aabb\n{\"hello\":\"world\"}",
	},
	{
		Name:      "path-with-query-like-bytes-in-body",
		Product:   "dorsalmail",
		Method:    "POST",
		Path:      "/notify",
		Timestamp: 1700000100,
		Nonce:     "ffeeddccbbaa998877665544",
		Body:      []byte("line1\nline2"),
		Canonical: "dorsalmail\nPOST\n/notify\n1700000100\nffeeddccbbaa998877665544\nline1\nline2",
	},
	{
		// Product-agnostic vector: exercises the signing primitive under a
		// second product id so consumers prove their codepath is not
		// dorsalmail-bound.
		Name:      "basic-post-dorsalforms",
		Product:   "dorsalforms",
		Method:    "POST",
		Path:      "/submit",
		Timestamp: 1700000200,
		Nonce:     "aabbccddeeff00112233445566778899",
		Body:      []byte(`{"form_id":"abc"}`),
		Canonical: "dorsalforms\nPOST\n/submit\n1700000200\naabbccddeeff00112233445566778899\n{\"form_id\":\"abc\"}",
	},
}

var ReplayVectors = []ReplayVector{
	{
		Name:          "cached-same-body",
		RequestBody:   []byte(`{"mode":"transit","id":1}`),
		StoredBody:    []byte(`{"id":"email-1","status":"sent"}`),
		StoredStatus:  200,
		Conflict:      false,
		Cached:        true,
		ExpectedState: "cached",
	},
	{
		Name:          "same-key-different-body",
		RequestBody:   []byte(`{"mode":"transit","id":2}`),
		StoredBody:    nil,
		StoredStatus:  0,
		Conflict:      true,
		Cached:        false,
		ExpectedState: "conflict",
	},
}

var AuditVectors = []AuditVector{
	{
		Name:      "secure-token-redaction",
		InputPath: "/v1/secure/abc123/otp",
		Redacted:  "/v1/secure/:token/otp",
		Event: coreaudit.Event{
			EventID:      uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
			EventType:    "http.request",
			RequestID:    "req-1",
			ActorType:    "api_key",
			Method:       "POST",
			Path:         "/v1/secure/:token/otp",
			RoutePattern: "/v1/secure/{token}/otp/send",
			Outcome:      "success",
			StatusCode:   200,
		},
		PrevHash:     "",
		ExpectedHash: "dd54ac98cf3bb4dfdc0d17a3f85f7ba1f4d5bc6304d30705b40c991d6f1d4ff4",
	},
}

var TransitHashVectors = []TransitHashVector{
	{
		Name:      "normalized-principal",
		MasterHex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		OrgID:     uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Principal: " User@Example.com ",
	},
}
