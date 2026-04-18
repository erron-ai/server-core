// Package bootstrap implements the server→enclave handshake that delivers
// the MAC key (aka "AuthKey") used to sign subsequent server→enclave
// requests. The transport is X25519 ephemeral DH → HKDF-SHA-256 → AES-256-GCM.
//
// PII contract: the plaintext AuthKey recovered by the server is a MAC key
// for server→enclave request signing. It is NOT an encryption key and MUST
// NOT be used to decrypt PII or to derive any key capable of decrypting PII.
package bootstrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// channelInfo and payloadAAD are bound into the HKDF `info` and AES-GCM AAD.
// They MUST match the enclave-rs side byte-for-byte; the names are
// product-neutral (dorsal-*) so Forms/Files/Chat can adopt the primitive
// without rebinding the transcript to a Mail-specific string.
const (
	channelInfo = "dorsal-bootstrap-channel-v1"
	payloadAAD  = "dorsal-bootstrap-payload-v1"
)

type SetupRequest struct {
	ServerEphemeralPublic string `json:"server_ephem_pub"`
}

type SetupResponse struct {
	EnclaveEphemeralPublic string `json:"enclave_ephem_pub"`
	SessionID              string `json:"session_id"`
}

type BootstrapRequest struct {
	SessionID string `json:"session_id"`
}

type BootstrapResponse struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type Session struct {
	ServerEphemeralPrivate [32]byte
	ServerEphemeralPublic  [32]byte
	EnclaveEphemeralPublic [32]byte
	SessionID              [16]byte
}

func NewSetupRequest() (SetupRequest, [32]byte, error) {
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return SetupRequest{}, [32]byte{}, fmt.Errorf("bootstrap private key: %w", err)
	}
	publicKey, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return SetupRequest{}, [32]byte{}, fmt.Errorf("bootstrap public key: %w", err)
	}
	var public [32]byte
	copy(public[:], publicKey)
	return SetupRequest{ServerEphemeralPublic: hex.EncodeToString(public[:])}, privateKey, nil
}

func ParseSetupResponse(raw []byte, privateKey [32]byte) (Session, error) {
	var response SetupResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return Session{}, fmt.Errorf("bootstrap setup response: %w", err)
	}
	enclavePublicBytes, err := decodeHexSized(response.EnclaveEphemeralPublic, "enclave_ephem_pub", 32)
	if err != nil {
		return Session{}, err
	}
	sessionIDBytes, err := decodeHexSized(response.SessionID, "session_id", 16)
	if err != nil {
		return Session{}, err
	}
	serverPublic, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return Session{}, fmt.Errorf("bootstrap server public key: %w", err)
	}
	var public [32]byte
	var enclavePublic [32]byte
	var sessionID [16]byte
	copy(public[:], serverPublic)
	copy(enclavePublic[:], enclavePublicBytes)
	copy(sessionID[:], sessionIDBytes)
	return Session{
		ServerEphemeralPrivate: privateKey,
		ServerEphemeralPublic:  public,
		EnclaveEphemeralPublic: enclavePublic,
		SessionID:              sessionID,
	}, nil
}

func (s Session) Request() BootstrapRequest {
	return BootstrapRequest{SessionID: hex.EncodeToString(s.SessionID[:])}
}

func (s Session) ChannelKey() ([32]byte, error) {
	shared, err := curve25519.X25519(s.ServerEphemeralPrivate[:], s.EnclaveEphemeralPublic[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("bootstrap shared secret: %w", err)
	}
	reader := hkdf.New(sha256New, shared, s.EnclaveEphemeralPublic[:], []byte(channelInfo))
	var key [32]byte
	if _, err := io.ReadFull(reader, key[:]); err != nil {
		return [32]byte{}, fmt.Errorf("bootstrap channel key: %w", err)
	}
	return key, nil
}

func ParseBootstrapResponse(raw []byte) (BootstrapResponse, error) {
	var response BootstrapResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return BootstrapResponse{}, fmt.Errorf("bootstrap response: %w", err)
	}
	if _, err := decodeHexSized(response.Nonce, "nonce", 12); err != nil {
		return BootstrapResponse{}, err
	}
	if _, err := hex.DecodeString(response.Ciphertext); err != nil {
		return BootstrapResponse{}, fmt.Errorf("ciphertext: %w", err)
	}
	return response, nil
}

func DecryptAuthKey(session Session, response BootstrapResponse) (string, error) {
	channelKey, err := session.ChannelKey()
	if err != nil {
		return "", err
	}
	nonceBytes, err := decodeHexSized(response.Nonce, "nonce", 12)
	if err != nil {
		return "", err
	}
	ciphertext, err := hex.DecodeString(response.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("ciphertext: %w", err)
	}
	block, err := aes.NewCipher(channelKey[:])
	if err != nil {
		return "", fmt.Errorf("bootstrap cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("bootstrap gcm: %w", err)
	}
	aad := append([]byte{0x01}, []byte(payloadAAD)...)
	plaintext, err := gcm.Open(nil, nonceBytes, ciphertext, aad)
	if err != nil {
		return "", fmt.Errorf("bootstrap decrypt: %w", err)
	}
	if len(plaintext) == 0 {
		return "", fmt.Errorf("bootstrap response contained empty auth key")
	}
	return hex.EncodeToString(plaintext), nil
}

func decodeHexSized(value string, field string, size int) ([]byte, error) {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	if len(raw) != size {
		return nil, fmt.Errorf("%s: expected %d bytes, got %d", field, size, len(raw))
	}
	return raw, nil
}

func sha256New() hash.Hash {
	return sha256.New()
}
