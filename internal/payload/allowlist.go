// Copyright 2026 The PLIMSOLL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package payload

import (
	"encoding/json"
	"fmt"
	"strings"
)

var (
	sealPublishAllowed = map[string]struct{}{
		"seal_hash": {}, "canonical_b64": {}, "submitter_id": {},
		"submitted_at": {}, "supersedes": {}, "signature_b64": {},
		"public_key_b64": {},
	}
	attestPublishAllowed = map[string]struct{}{
		"seal_hash": {}, "result_digest": {}, "verdict": {},
		"canonical_b64": {}, "signature_b64": {},
	}
)

// AssertSealPublish checks outbound JSON contains only allowlisted top-level keys
// and no forbidden substrings (row content markers).
func AssertSealPublish(body []byte) error {
	return assertPayload(body, sealPublishAllowed, "seal publish")
}

// AssertAttestationPublish checks outbound attestation submit payload.
func AssertAttestationPublish(body []byte) error {
	return assertPayload(body, attestPublishAllowed, "attestation publish")
}

func assertPayload(body []byte, allowed map[string]struct{}, label string) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return fmt.Errorf("payload: %s: invalid json: %w", label, err)
	}
	for k := range top {
		if _, ok := allowed[k]; !ok {
			return fmt.Errorf("payload: %s: forbidden field %q", label, k)
		}
	}
	lower := strings.ToLower(string(body))
	for _, forbidden := range []string{
		"\"input\"", "\"output\"", "\"prompt\"", "\"actualoutput\"",
		"\"actual_output\"", "\"text\"", "\"messages\"", "\"rows\"",
		"\"raw\"", "\"dataset\"", "\"attempt\"",
		"\"attempt_no\"",
	} {
		if strings.Contains(lower, forbidden) {
			return fmt.Errorf("payload: %s: contains forbidden token %s", label, forbidden)
		}
	}
	return nil
}

// AllOutbound returns every payload that would be sent for publishing a seal
// and attestation. Tests assert each against the allowlist.
func AllOutbound(sealBody, attestBody []byte) [][]byte {
	var out [][]byte
	if len(sealBody) > 0 {
		out = append(out, sealBody)
	}
	if len(attestBody) > 0 {
		out = append(out, attestBody)
	}
	return out
}
