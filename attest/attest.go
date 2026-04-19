// Package attest implements input-validation for the attestation-challenge
// proxy flow. The Go server never generates or inspects attestation content;
// it validates the client-supplied challenge shape and forwards the request
// to the enclave.
//
// PII contract: opaque input — challenges are client-generated random nonces
// and carry no PII. This package guards against oversized / non-base64 /
// too-short challenges at the server boundary before forwarding.
package attest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	coreerrors "github.com/erron-ai/server-core/errors"
)

const (
	MinChallengeBytes       = 32
	MaxEncodedChallengeSize = 512
)

type ChallengeRequest struct {
	Challenge string `json:"challenge"`
}

func ParseChallengeRequest(raw []byte) (ChallengeRequest, []byte, error) {
	var req ChallengeRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return ChallengeRequest{}, nil, coreerrors.Wrap(coreerrors.CodeInvalidJSON, "invalid challenge request", err)
	}
	trimmed := strings.TrimSpace(req.Challenge)
	if trimmed == "" {
		return ChallengeRequest{}, nil, coreerrors.New(coreerrors.CodeInvalidField, "challenge required")
	}
	if len(trimmed) > MaxEncodedChallengeSize {
		return ChallengeRequest{}, nil, coreerrors.New(coreerrors.CodeInvalidField, "challenge too long")
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return ChallengeRequest{}, nil, coreerrors.Wrap(coreerrors.CodeInvalidField, "challenge must be valid base64", err)
	}
	if len(decoded) < MinChallengeBytes {
		return ChallengeRequest{}, nil, coreerrors.New(
			coreerrors.CodeInvalidField,
			fmt.Sprintf("challenge must be >= %d raw bytes", MinChallengeBytes),
		)
	}
	req.Challenge = trimmed
	return req, decoded, nil
}

func ErrorCode(err error) string {
	return coreerrors.CodeOf(err)
}
