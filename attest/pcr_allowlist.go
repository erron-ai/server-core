package attest

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// ParsePCRAllowlistJSON parses a JSON array of PCR maps. Each element is an
// object whose keys are decimal PCR indices ("0", "1", …) and values are
// hex-encoded measurements (same encoding as the Nitro attestation document).
//
// Example: `[{"0":"aabb…","1":"ccdd…"}]` allows two alternative images.
func ParsePCRAllowlistJSON(raw string) ([]PCRSet, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var entries []map[string]string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, fmt.Errorf("attest: ATTESTATION_PCR_ALLOWLIST: %w", err)
	}
	out := make([]PCRSet, 0, len(entries))
	for _, e := range entries {
		ps := make(PCRSet)
		for k, v := range e {
			var idx int
			if _, err := fmt.Sscanf(k, "%d", &idx); err != nil || idx < 0 || idx > 31 {
				return nil, fmt.Errorf("attest: invalid pcr index %q", k)
			}
			b, err := hex.DecodeString(strings.TrimSpace(v))
			if err != nil {
				return nil, fmt.Errorf("attest: pcr %d: %w", idx, err)
			}
			ps[idx] = b
		}
		if len(ps) == 0 {
			return nil, fmt.Errorf("attest: empty pcr set in allowlist")
		}
		out = append(out, ps)
	}
	return out, nil
}
