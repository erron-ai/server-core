package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// nitroAttestationDoc is the CBOR attestation payload inside COSE_Sign1 (AWS spec).
type nitroAttestationDoc struct {
	ModuleID    string         `cbor:"module_id"`
	Timestamp   uint64       `cbor:"timestamp"`
	Digest      string       `cbor:"digest"`
	PCRsRaw     cbor.RawMessage `cbor:"pcrs"`
	Certificate []byte       `cbor:"certificate"`
	CABundle    [][]byte     `cbor:"cabundle"`
	Nonce       []byte       `cbor:"nonce,omitempty"`
	PublicKey   []byte       `cbor:"public_key,omitempty"`
	UserData    []byte       `cbor:"user_data,omitempty"`
}

func verifyNitroCOSE(
	doc []byte,
	rootPEM []byte,
	expectedNonce []byte,
	allow []PCRSet,
	maxAge time.Duration,
	now time.Time,
) (Measurements, error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(doc); err != nil {
		return Measurements{}, fmt.Errorf("%w: cose: %v", ErrMalformedDoc, err)
	}
	if len(msg.Payload) == 0 {
		return Measurements{}, ErrMalformedDoc
	}

	var inner nitroAttestationDoc
	if err := cbor.Unmarshal(msg.Payload, &inner); err != nil {
		return Measurements{}, fmt.Errorf("%w: inner cbor: %v", ErrMalformedDoc, err)
	}
	pcrMap, err := decodePCRMap(inner.PCRsRaw)
	if err != nil {
		return Measurements{}, err
	}
	if err := validateNitroAttestationShape(&inner, len(pcrMap)); err != nil {
		return Measurements{}, err
	}

	leaf, err := x509.ParseCertificate(inner.Certificate)
	if err != nil {
		return Measurements{}, fmt.Errorf("%w: leaf cert: %v", ErrMalformedDoc, err)
	}
	if err := verifyNitroCertChain(leaf, inner.CABundle, rootPEM, now); err != nil {
		return Measurements{}, err
	}

	alg := cose.AlgorithmES384
	if a, err := msg.Headers.Protected.Algorithm(); err == nil && a != 0 {
		alg = a
	}
	if alg != cose.AlgorithmES384 {
		return Measurements{}, fmt.Errorf("%w: unsupported COSE alg %d (want ES384)", ErrMalformedDoc, alg)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return Measurements{}, fmt.Errorf("%w: leaf not ECDSA", ErrMalformedDoc)
	}
	verifier, err := cose.NewVerifier(alg, pub)
	if err != nil {
		return Measurements{}, err
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return Measurements{}, fmt.Errorf("%w: %v", ErrMalformedDoc, err)
	}

	if len(expectedNonce) > 0 {
		if len(inner.Nonce) == 0 || !bytes.Equal(inner.Nonce, expectedNonce) {
			return Measurements{}, ErrNonceMismatch
		}
	}

	if inner.Timestamp > math.MaxInt64 {
		return Measurements{}, ErrMalformedDoc
	}
	issued := time.UnixMilli(int64(inner.Timestamp)).UTC()
	if maxAge > 0 && now.Sub(issued) > maxAge {
		return Measurements{}, ErrTooOld
	}

	if len(allow) > 0 {
		if !pcrMatchesAny(pcrMap, allow) {
			return Measurements{}, ErrPCRMismatch
		}
	}

	return Measurements{
		PCRs:     PCRSet(pcrMap),
		ModuleID: inner.ModuleID,
		Digest:   inner.Digest,
		IssuedAt: issued,
	}, nil
}

func decodePCRMap(raw cbor.RawMessage) (map[int][]byte, error) {
	if len(raw) == 0 {
		return nil, ErrMalformedDoc
	}
	var asMap map[uint64][]byte
	if err := cbor.Unmarshal(raw, &asMap); err != nil {
		var asMapInt map[int][]byte
		if err2 := cbor.Unmarshal(raw, &asMapInt); err2 != nil {
			return nil, fmt.Errorf("%w: pcrs: %v", ErrMalformedDoc, err)
		}
		return asMapInt, nil
	}
	out := make(map[int][]byte, len(asMap))
	for k, v := range asMap {
		if k > uint64(math.MaxInt) {
			return nil, fmt.Errorf("%w: pcr slot out of range", ErrMalformedDoc)
		}
		out[int(k)] = v
	}
	return out, nil
}

func validateNitroAttestationShape(d *nitroAttestationDoc, pcrCount int) error {
	if d.ModuleID == "" || d.Digest == "" || d.Timestamp == 0 {
		return ErrMalformedDoc
	}
	if d.Digest != "SHA384" {
		return fmt.Errorf("%w: digest must be SHA384", ErrMalformedDoc)
	}
	if len(d.Certificate) == 0 || len(d.CABundle) == 0 {
		return ErrMalformedDoc
	}
	if pcrCount == 0 {
		return ErrMalformedDoc
	}
	return nil
}

func verifyNitroCertChain(leaf *x509.Certificate, cabundle [][]byte, rootPEM []byte, now time.Time) error {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return errors.New("attest: invalid root PEM pool")
	}
	inters := x509.NewCertPool()
	for _, der := range cabundle {
		if len(der) == 0 {
			continue
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("attest: cabundle cert: %w", err)
		}
		inters.AddCert(c)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedDoc, err)
	}
	return nil
}
