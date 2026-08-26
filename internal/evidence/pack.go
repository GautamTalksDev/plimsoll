// Copyright 2026 The PLIMSOLL Authors
// SPDX-License-Identifier: Apache-2.0
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

// Package evidence builds self-contained evidence packs from a transparency log.
package evidence

import (
	"encoding/json"

	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/sealfile"
	"github.com/GautamTalksDev/plimsoll/internal/verify"
)

const Version = "plimsoll-evidence-v1"

// Pack is a self-contained evidence artifact for one seal.
type Pack struct {
	Version            string          `json:"version"`
	GeneratedAt        int64           `json:"generated_at"`
	LogURL             string          `json:"log_url,omitempty"`
	LogPublicKey       string          `json:"log_public_key"`
	BrowserVerifierURL string          `json:"browser_verifier_url"`
	SealHash           string          `json:"seal_hash"`
	Preregistration    Preregistration `json:"preregistration"`
	SealInclusion      InclusionRecord `json:"seal_inclusion"`
	Attempts           []AttemptRecord `json:"attempts"`
	SupersedeChain     []SupersedeLink `json:"supersede_chain,omitempty"`
	Instructions       []string        `json:"instructions"`
	VerifyURL          string          `json:"verify_url,omitempty"`
}

// Preregistration is the signed pre-registration in human-readable and raw forms.
type Preregistration struct {
	YAML         string             `json:"yaml"`
	SealDocument *sealfile.Document `json:"seal_document"`
}

// InclusionRecord binds a log entry to a signed checkpoint.
type InclusionRecord struct {
	LogIndex    int64                         `json:"log_index"`
	SubmittedAt int64                         `json:"submitted_at"`
	Proof       sealfile.StoredInclusionProof `json:"inclusion_proof"`
	Checkpoint  log.Checkpoint                `json:"checkpoint"`
}

// AttemptRecord is one attested evaluation attempt with proofs and verification.
type AttemptRecord struct {
	AttemptNo    int             `json:"attempt_no"`
	SubmittedAt  int64           `json:"submitted_at"`
	Verdict      string          `json:"verdict"`
	ResultDigest string          `json:"result_digest"`
	Attestation  json.RawMessage `json:"attestation"`
	Inclusion    InclusionRecord `json:"inclusion"`
	Verification verify.Report   `json:"verification"`
	VerifyURL    string          `json:"verify_url"`
}

// SupersedeLink is one hop in a supersede chain (oldest first).
type SupersedeLink struct {
	SealHash        string `json:"seal_hash"`
	Supersedes      string `json:"supersedes,omitempty"`
	SupersedeReason string `json:"supersede_reason,omitempty"`
	SubmittedAt     int64  `json:"submitted_at"`
}
