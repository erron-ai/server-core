package bootstrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func TestSetupRoundTripAndDecrypt(t *testing.T) {
	setupRequest, privateKey, err := NewSetupRequest()
	if err != nil {
		t.Fatalf("NewSetupRequest: %v", err)
	}

	serverPublicBytes, err := hex.DecodeString(setupRequest.ServerEphemeralPublic)
	if err != nil {
		t.Fatalf("decode server public: %v", err)
	}

	enclavePrivate := [32]byte{}
	for i := range enclavePrivate {
		enclavePrivate[i] = byte(i + 1)
	}
	enclavePublic, err := curve25519.X25519(enclavePrivate[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519 enclave public: %v", err)
	}

	setupBody, err := json.Marshal(SetupResponse{
		EnclaveEphemeralPublic: hex.EncodeToString(enclavePublic),
		SessionID:              "00112233445566778899aabbccddeeff",
	})
	if err != nil {
		t.Fatalf("marshal setup response: %v", err)
	}

	session, err := ParseSetupResponse(setupBody, privateKey)
	if err != nil {
		t.Fatalf("ParseSetupResponse: %v", err)
	}

	if got := hex.EncodeToString(session.ServerEphemeralPublic[:]); got != hex.EncodeToString(serverPublicBytes) {
		t.Fatalf("server public mismatch: got %s want %s", got, hex.EncodeToString(serverPublicBytes))
	}

	authKey := bytesRepeat(0xee, 32)
	channelKey, err := session.ChannelKey()
	if err != nil {
		t.Fatalf("ChannelKey: %v", err)
	}
	nonce := [12]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	ciphertext, err := encryptBootstrapPayload(channelKey, nonce, authKey)
	if err != nil {
		t.Fatalf("encrypt bootstrap payload: %v", err)
	}

	bootstrapBody, err := json.Marshal(BootstrapResponse{
		Nonce:      hex.EncodeToString(nonce[:]),
		Ciphertext: hex.EncodeToString(ciphertext),
	})
	if err != nil {
		t.Fatalf("marshal bootstrap response: %v", err)
	}

	parsedBootstrap, err := ParseBootstrapResponse(bootstrapBody)
	if err != nil {
		t.Fatalf("ParseBootstrapResponse: %v", err)
	}

	authKeyHex, err := DecryptAuthKey(session, parsedBootstrap)
	if err != nil {
		t.Fatalf("DecryptAuthKey: %v", err)
	}
	if authKeyHex != hex.EncodeToString(authKey) {
		t.Fatalf("auth key mismatch: got %s want %s", authKeyHex, hex.EncodeToString(authKey))
	}
}

func TestDecryptAuthKeyRejectsBadCiphertext(t *testing.T) {
	_, privateKey, err := NewSetupRequest()
	if err != nil {
		t.Fatalf("NewSetupRequest: %v", err)
	}

	enclavePrivate := [32]byte{}
	for i := range enclavePrivate {
		enclavePrivate[i] = byte(i + 10)
	}
	enclavePublic, err := curve25519.X25519(enclavePrivate[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519 enclave public: %v", err)
	}

	setupBody, err := json.Marshal(SetupResponse{
		EnclaveEphemeralPublic: hex.EncodeToString(enclavePublic),
		SessionID:              "00112233445566778899aabbccddeeff",
	})
	if err != nil {
		t.Fatalf("marshal setup response: %v", err)
	}

	session, err := ParseSetupResponse(setupBody, privateKey)
	if err != nil {
		t.Fatalf("ParseSetupResponse: %v", err)
	}

	bootstrapResponse := BootstrapResponse{
		Nonce:      "000102030405060708090a0b",
		Ciphertext: stringsRepeat("00", 48),
	}
	if _, err := DecryptAuthKey(session, bootstrapResponse); err == nil {
		t.Fatal("expected decrypt failure")
	}
}

func TestParseSetupResponseRejectsWrongSizes(t *testing.T) {
	_, privateKey, err := NewSetupRequest()
	if err != nil {
		t.Fatalf("NewSetupRequest: %v", err)
	}
	raw, err := json.Marshal(SetupResponse{
		EnclaveEphemeralPublic: "aa",
		SessionID:              "bb",
	})
	if err != nil {
		t.Fatalf("marshal setup response: %v", err)
	}
	if _, err := ParseSetupResponse(raw, privateKey); err == nil {
		t.Fatal("expected parse failure")
	}
}

func TestParseBootstrapResponse_RejectsOddLengthCiphertextHex(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(BootstrapResponse{
		Nonce:      "000102030405060708090a0b",
		Ciphertext: "a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBootstrapResponse(raw); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseBootstrapResponse_RejectsWrongNonceLength(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(BootstrapResponse{
		Nonce:      "00010203040506",
		Ciphertext: stringsRepeat("00", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBootstrapResponse(raw); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptAuthKey_WrongAADFails(t *testing.T) {
	_, privateKey, err := NewSetupRequest()
	if err != nil {
		t.Fatalf("NewSetupRequest: %v", err)
	}
	enclavePrivate := [32]byte{}
	for i := range enclavePrivate {
		enclavePrivate[i] = byte(i + 1)
	}
	enclavePublic, err := curve25519.X25519(enclavePrivate[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	setupBody, err := json.Marshal(SetupResponse{
		EnclaveEphemeralPublic: hex.EncodeToString(enclavePublic),
		SessionID:              "00112233445566778899aabbccddeeff",
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := ParseSetupResponse(setupBody, privateKey)
	if err != nil {
		t.Fatalf("ParseSetupResponse: %v", err)
	}
	channelKey, err := session.ChannelKey()
	if err != nil {
		t.Fatal(err)
	}
	authKey := bytesRepeat(0xee, 32)
	nonce := [12]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	ct, err := encryptBootstrapPayloadWrongAAD(channelKey, nonce, authKey)
	if err != nil {
		t.Fatal(err)
	}
	resp := BootstrapResponse{
		Nonce:      hex.EncodeToString(nonce[:]),
		Ciphertext: hex.EncodeToString(ct),
	}
	if _, err := DecryptAuthKey(session, resp); err == nil {
		t.Fatal("expected decrypt failure")
	}
}

func TestSessionRequest_RoundTripsSessionID(t *testing.T) {
	t.Parallel()
	_, privateKey, err := NewSetupRequest()
	if err != nil {
		t.Fatalf("NewSetupRequest: %v", err)
	}
	enclavePrivate := [32]byte{}
	for i := range enclavePrivate {
		enclavePrivate[i] = byte(i + 3)
	}
	enclavePublic, err := curve25519.X25519(enclavePrivate[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	wantSession := "00112233445566778899aabbccddeeff"
	setupBody, err := json.Marshal(SetupResponse{
		EnclaveEphemeralPublic: hex.EncodeToString(enclavePublic),
		SessionID:              wantSession,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := ParseSetupResponse(setupBody, privateKey)
	if err != nil {
		t.Fatalf("ParseSetupResponse: %v", err)
	}
	if got := session.Request().SessionID; got != wantSession {
		t.Fatalf("SessionID = %q, want %q", got, wantSession)
	}
}

func encryptBootstrapPayloadWrongAAD(channelKey [32]byte, nonce [12]byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(channelKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := append([]byte{0x02}, []byte("wrong-aad")...)
	return gcm.Seal(nil, nonce[:], plaintext, aad), nil
}

func encryptBootstrapPayload(channelKey [32]byte, nonce [12]byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(channelKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := append([]byte{0x01}, []byte(payloadAAD)...)
	return gcm.Seal(nil, nonce[:], plaintext, aad), nil
}

func bytesRepeat(b byte, size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = b
	}
	return out
}

func stringsRepeat(s string, count int) string {
	out := ""
	for i := 0; i < count; i++ {
		out += s
	}
	return out
}

func TestChannelKeyMatchesExpectedHKDF(t *testing.T) {
	var privateKey [32]byte
	for i := range privateKey {
		privateKey[i] = byte(2*i + 1)
	}
	serverPublic, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("server public: %v", err)
	}
	var enclavePublic [32]byte
	for i := range enclavePublic {
		enclavePublic[i] = byte(200 - i)
	}
	session := Session{
		ServerEphemeralPrivate: privateKey,
		SessionID:              [16]byte{},
	}
	copy(session.ServerEphemeralPublic[:], serverPublic)
	copy(session.EnclaveEphemeralPublic[:], enclavePublic[:])

	got, err := session.ChannelKey()
	if err != nil {
		t.Fatalf("ChannelKey: %v", err)
	}

	shared, err := curve25519.X25519(privateKey[:], enclavePublic[:])
	if err != nil {
		t.Fatalf("shared: %v", err)
	}
	reader := hkdf.New(sha256.New, shared, enclavePublic[:], []byte(channelInfo))
	var want [32]byte
	if _, err := io.ReadFull(reader, want[:]); err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	if got != want {
		t.Fatalf("channel key mismatch")
	}
}
