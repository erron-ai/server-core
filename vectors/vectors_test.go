package vectors

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coreattest "github.com/erron-ai/server-core/attest"
	coreaudit "github.com/erron-ai/server-core/audit"
	coreauth "github.com/erron-ai/server-core/auth"
	corebootstrap "github.com/erron-ai/server-core/bootstrap"
	coreplay "github.com/erron-ai/server-core/replay"
	coretracking "github.com/erron-ai/server-core/tracking"
	"github.com/google/uuid"
)

type clickVector struct {
	Name     string `json:"name"`
	KeyHex   string `json:"key_hex"`
	EmailID  string `json:"email_id"`
	Target   string `json:"target"`
	Kind     string `json:"kind"`
	Token    string `json:"token"`
	URL      string `json:"url"`
	Verifies bool   `json:"verifies"`
	BaseURL  string `json:"base_url"`
}

type clickVectorFile struct {
	Vectors []clickVector `json:"vectors"`
}

func TestVectorsIssueClickAndPixelURLs(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "click_v1.json"))
	if err != nil {
		t.Fatalf("read click_v1.json: %v", err)
	}
	var file clickVectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("unmarshal click_v1.json: %v", err)
	}
	for _, v := range file.Vectors {
		if !v.Verifies {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			id := uuid.MustParse(v.EmailID)
			switch v.Kind {
			case "click":
				gotURL, err := coretracking.IssueClickURL(id, v.Target, v.KeyHex, v.BaseURL)
				if err != nil {
					t.Fatalf("IssueClickURL: %v", err)
				}
				u, err := url.Parse(gotURL)
				if err != nil {
					t.Fatal(err)
				}
				exp, err := url.Parse(v.URL)
				if err != nil {
					t.Fatal(err)
				}
				if u.Scheme != exp.Scheme || u.Host != exp.Host || u.Path != exp.Path {
					t.Fatalf("url mismatch\n got: %s\nwant: %s", gotURL, v.URL)
				}
				gotTok := strings.TrimPrefix(u.Path, "/v1/tracking/click/")
				if i := strings.IndexByte(gotTok, '?'); i >= 0 {
					gotTok = gotTok[:i]
				}
				if gotTok != v.Token {
					t.Fatalf("token mismatch\n got: %s\nwant: %s", gotTok, v.Token)
				}
				if u.Query().Get("u") != v.Target {
					t.Fatalf("target query mismatch")
				}
			case "pixel":
				gotURL, err := coretracking.IssuePixelURL(id, v.KeyHex, v.BaseURL)
				if err != nil {
					t.Fatalf("IssuePixelURL: %v", err)
				}
				u, err := url.Parse(gotURL)
				if err != nil {
					t.Fatal(err)
				}
				exp, err := url.Parse(v.URL)
				if err != nil {
					t.Fatal(err)
				}
				if u.Scheme != exp.Scheme || u.Host != exp.Host || u.Path != exp.Path {
					t.Fatalf("url mismatch\n got: %s\nwant: %s", gotURL, v.URL)
				}
				gotTok := strings.TrimPrefix(u.Path, "/v1/tracking/pixel/")
				if gotTok != v.Token {
					t.Fatalf("token mismatch\n got: %s\nwant: %s", gotTok, v.Token)
				}
			default:
				t.Fatalf("unknown kind %q", v.Kind)
			}
		})
	}
}

func TestVectorsTrackingClickV1(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "click_v1.json"))
	if err != nil {
		t.Fatalf("read click_v1.json: %v", err)
	}
	var file clickVectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("unmarshal click_v1.json: %v", err)
	}
	if len(file.Vectors) < 5 {
		t.Fatalf("expected >= 5 vectors, got %d", len(file.Vectors))
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			id := uuid.MustParse(v.EmailID)
			switch v.Kind {
			case "click":
				gotID, err := coretracking.VerifyClickRequest(v.Token, v.Target, v.KeyHex)
				if v.Verifies {
					if err != nil {
						t.Fatalf("expected verify success: %v", err)
					}
					if gotID != id {
						t.Fatalf("id mismatch: %v vs %v", gotID, id)
					}
				} else if err == nil {
					t.Fatal("expected verify failure")
				}
			case "pixel":
				gotID, err := coretracking.VerifyPixelRequest(v.Token, v.KeyHex)
				if v.Verifies {
					if err != nil {
						t.Fatalf("expected verify success: %v", err)
					}
					if gotID != id {
						t.Fatalf("id mismatch")
					}
				} else if err == nil {
					t.Fatal("expected verify failure")
				}
			default:
				t.Fatalf("unknown vector kind %q", v.Kind)
			}
		})
	}
}

func TestVectorsCanonicalRequest(t *testing.T) {
	signed, err := coreauth.SignRequest(
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		"dorsalmail",
		"POST",
		"/transit",
		[]byte(`{"hello":"world"}`),
		coreauth.SignOptions{
			Nonce: "00112233445566778899aabb",
		},
	)
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if signed.Nonce != "00112233445566778899aabb" {
		t.Fatalf("unexpected nonce: %s", signed.Nonce)
	}
	if signed.Signature == "" {
		t.Fatal("expected signature")
	}
}

type transitSigVector struct {
	Name         string `json:"name"`
	KeyHex       string `json:"key_hex"`
	Product      string `json:"product"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	Timestamp    int64  `json:"timestamp"`
	Nonce        string `json:"nonce"`
	Body         string `json:"body"`
	CanonicalHex string `json:"canonical_hex"`
	SignatureHex string `json:"signature_hex"`
}

type transitSigFile struct {
	Vectors []transitSigVector `json:"vectors"`
}

func TestVectorsTransitSignatureJSON(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "transit_signature.json"))
	if err != nil {
		t.Fatalf("read transit_signature.json: %v", err)
	}
	var file transitSigFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("unmarshal transit_signature.json: %v", err)
	}
	if len(file.Vectors) < 2 {
		t.Fatalf("expected >=2 vectors, got %d", len(file.Vectors))
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			canonical := coreauth.CanonicalRequest(v.Product, v.Method, v.Path, v.Timestamp, v.Nonce, []byte(v.Body))
			if got := hex.EncodeToString(canonical); got != v.CanonicalHex {
				t.Fatalf("canonical_hex mismatch\n got: %s\nwant: %s", got, v.CanonicalHex)
			}
			signed, err := coreauth.SignRequest(v.KeyHex, v.Product, v.Method, v.Path, []byte(v.Body), coreauth.SignOptions{
				Now:   time.Unix(v.Timestamp, 0).UTC(),
				Nonce: v.Nonce,
			})
			if err != nil {
				t.Fatalf("SignRequest: %v", err)
			}
			if signed.Signature != v.SignatureHex {
				t.Fatalf("signature mismatch\n got: %s\nwant: %s", signed.Signature, v.SignatureHex)
			}
		})
	}
}

func TestVectorsReplayConflict(t *testing.T) {
	first := coreplay.FingerprintBody([]byte(`{"mode":"transit"}`))
	second := coreplay.FingerprintBody([]byte(`{"mode":"secure"}`))
	decision := coreplay.ClassifyExisting(second, first, 0, nil)
	if decision.Outcome != coreplay.OutcomeConflict {
		t.Fatalf("expected conflict, got %s", decision.Outcome)
	}
}

func TestVectorsAttestationValidation(t *testing.T) {
	raw, err := json.Marshal(map[string]string{
		"challenge": base64.StdEncoding.EncodeToString(make([]byte, coreattest.MinChallengeBytes)),
	})
	if err != nil {
		t.Fatalf("marshal challenge: %v", err)
	}
	req, decoded, err := coreattest.ParseChallengeRequest(raw)
	if err != nil {
		t.Fatalf("ParseChallengeRequest: %v", err)
	}
	if req.Challenge == "" || len(decoded) != coreattest.MinChallengeBytes {
		t.Fatal("expected valid challenge vector")
	}
}

func TestVectorsAuditHashStable(t *testing.T) {
	orgID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	event := coreaudit.NormalizeEvent(coreaudit.Event{
		EventType:    "http.request",
		OrgID:        &orgID,
		Method:       "GET",
		Path:         coreaudit.RedactPath("/v1/secure/token123/otp"),
		RoutePattern: "/v1/secure/{token}/otp/send",
		StatusCode:   200,
	})
	first := coreaudit.EntryHash(event, "")
	second := coreaudit.EntryHash(event, "")
	if first != second {
		t.Fatalf("expected stable entry hash, got %s vs %s", first, second)
	}
}

type auditEntryHashVector struct {
	Name         string `json:"name"`
	EventID      string `json:"event_id"`
	OrgID        string `json:"org_id"`
	APIKeyID     string `json:"api_key_id"`
	EventType    string `json:"event_type"`
	CreatedAt    string `json:"created_at"`
	ActorType    string `json:"actor_type"`
	ActorID      string `json:"actor_id"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	RoutePattern string `json:"route_pattern"`
	StatusCode   int    `json:"status_code"`
	Outcome      string `json:"outcome"`
	ErrorCode    string `json:"error_code"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Action       string `json:"action"`
	RequestID    string `json:"request_id"`
	TokenFP      string `json:"token_fingerprint"`
	IPHMACHex    string `json:"ip_hmac_hex"`
	IPECIESHex   string `json:"ip_org_ecies_hex"`
	PrevHash     string `json:"prev_hash"`
	PreimageHex  string `json:"preimage_hex"`
	EntryHash    string `json:"entry_hash"`
}

type auditEntryHashFile struct {
	Vectors []auditEntryHashVector `json:"vectors"`
}

func TestVectorsAuditEntryHashGolden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "audit_entry_hash.json"))
	if err != nil {
		t.Fatalf("read audit_entry_hash.json: %v", err)
	}
	var file auditEntryHashFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("unmarshal audit_entry_hash.json: %v", err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("expected >=1 audit_entry_hash vector")
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			createdAt, err := time.Parse(time.RFC3339Nano, v.CreatedAt)
			if err != nil {
				t.Fatalf("parse created_at: %v", err)
			}
			var orgPtr *uuid.UUID
			if v.OrgID != "" {
				u := uuid.MustParse(v.OrgID)
				orgPtr = &u
			}
			var apiKeyPtr *uuid.UUID
			if v.APIKeyID != "" {
				u := uuid.MustParse(v.APIKeyID)
				apiKeyPtr = &u
			}
			ipHMAC, err := hex.DecodeString(v.IPHMACHex)
			if err != nil {
				t.Fatalf("decode ip_hmac_hex: %v", err)
			}
			ipECIES, err := hex.DecodeString(v.IPECIESHex)
			if err != nil {
				t.Fatalf("decode ip_org_ecies_hex: %v", err)
			}
			event := coreaudit.Event{
				EventID:          uuid.MustParse(v.EventID),
				EventType:        v.EventType,
				RequestID:        v.RequestID,
				OrgID:            orgPtr,
				APIKeyID:         apiKeyPtr,
				ActorType:        v.ActorType,
				ActorID:          v.ActorID,
				ResourceType:     v.ResourceType,
				ResourceID:       v.ResourceID,
				Action:           v.Action,
				Outcome:          v.Outcome,
				ErrorCode:        v.ErrorCode,
				Method:           v.Method,
				Path:             v.Path,
				RoutePattern:     v.RoutePattern,
				StatusCode:       v.StatusCode,
				IPHMAC:           ipHMAC,
				IPOrgECIES:       ipECIES,
				TokenFingerprint: v.TokenFP,
				CreatedAt:        createdAt,
			}
			preimage := coreaudit.Preimage(event, v.PrevHash)
			if got := hex.EncodeToString(preimage); got != v.PreimageHex {
				t.Fatalf("preimage mismatch\n got: %s\nwant: %s", got, v.PreimageHex)
			}
			if got := coreaudit.EntryHash(event, v.PrevHash); got != v.EntryHash {
				t.Fatalf("entry_hash mismatch\n got: %s\nwant: %s", got, v.EntryHash)
			}
		})
	}
}

func TestVectorsBootstrapCiphertextRejectsTampering(t *testing.T) {
	setupReq, privateKey, err := corebootstrap.NewSetupRequest()
	if err != nil {
		t.Fatalf("NewSetupRequest: %v", err)
	}
	serverPub, err := hex.DecodeString(setupReq.ServerEphemeralPublic)
	if err != nil {
		t.Fatalf("decode server pub: %v", err)
	}
	sessionResp := corebootstrap.SetupResponse{
		EnclaveEphemeralPublic: hex.EncodeToString(serverPub),
		SessionID:              "00112233445566778899aabbccddeeff",
	}
	raw, err := json.Marshal(sessionResp)
	if err != nil {
		t.Fatalf("marshal setup response: %v", err)
	}
	session, err := corebootstrap.ParseSetupResponse(raw, privateKey)
	if err != nil {
		t.Fatalf("ParseSetupResponse: %v", err)
	}
	response := corebootstrap.BootstrapResponse{
		Nonce:      "000102030405060708090a0b",
		Ciphertext: hex.EncodeToString([]byte("tampered-ciphertext")),
	}
	if _, err := corebootstrap.DecryptAuthKey(session, response); err == nil {
		t.Fatal("expected decrypt error for tampered ciphertext")
	}
}
