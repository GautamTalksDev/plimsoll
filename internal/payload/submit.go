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

// Package payload validates outbound/inbound log submit payloads.
package payload

import (
	"encoding/json"
	"fmt"
)

// SubmitKind classifies a POST /submit body.
type SubmitKind int

const (
	SubmitUnknown SubmitKind = iota
	SubmitSeal
	SubmitAttestation
)

// ClassifySubmit detects seal vs attestation by allowlisted keys present.
func ClassifySubmit(body []byte) (SubmitKind, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return SubmitUnknown, fmt.Errorf("payload: invalid json: %w", err)
	}
	has := func(k string) bool { _, ok := top[k]; return ok }
	switch {
	case has("public_key_b64"):
		return SubmitSeal, nil
	case has("result_digest") && has("verdict"):
		return SubmitAttestation, nil
	default:
		return SubmitUnknown, fmt.Errorf("payload: unrecognized submit shape")
	}
}

// AssertSubmit validates POST /submit bodies server-side.
func AssertSubmit(body []byte) (SubmitKind, error) {
	kind, err := ClassifySubmit(body)
	if err != nil {
		return SubmitUnknown, err
	}
	switch kind {
	case SubmitSeal:
		return kind, AssertSealPublish(body)
	case SubmitAttestation:
		return kind, AssertAttestationPublish(body)
	default:
		return SubmitUnknown, fmt.Errorf("payload: unknown submit kind")
	}
}
