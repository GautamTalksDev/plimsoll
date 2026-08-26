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

package staticlog

import (
	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/sealfile"
)

type checkpointFile struct {
	TreeSize     int64  `json:"tree_size"`
	RootHash     string `json:"root_hash"`
	Timestamp    int64  `json:"timestamp"`
	Signature    string `json:"signature"`
	LogPublicKey string `json:"log_public_key"`
}

type checkpointBare struct {
	TreeSize  int64  `json:"tree_size"`
	RootHash  string `json:"root_hash"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

type entriesPage struct {
	From     int64       `json:"from"`
	To       int64       `json:"to"`
	TreeSize int64       `json:"tree_size"`
	Page     int         `json:"page"`
	PageSize int         `json:"page_size"`
	Next     string      `json:"next,omitempty"`
	Entries  []log.Entry `json:"entries"`
}

type inclusionFile struct {
	InclusionProof sealfile.StoredInclusionProof `json:"inclusion_proof"`
	Checkpoint     checkpointBare                `json:"checkpoint"`
	LogPublicKey   string                        `json:"log_public_key"`
}

type consistencyFile struct {
	OldSize      int64    `json:"old_size"`
	NewSize      int64    `json:"new_size"`
	OldRoot      string   `json:"old_root"`
	NewRoot      string   `json:"new_root"`
	AuditPath    []string `json:"audit_path"`
	LogPublicKey string   `json:"log_public_key"`
}

type sealJSON struct {
	Index        int64  `json:"index"`
	SealHash     string `json:"seal_hash"`
	CanonicalB64 string `json:"canonical_b64"`
	SignatureB64 string `json:"signature_b64"`
	PublicKeyB64 string `json:"public_key_b64"`
	SubmitterID  string `json:"submitter_id"`
	SubmittedAt  int64  `json:"submitted_at"`
	Supersedes   string `json:"supersedes"`
	LeafHash     string `json:"leaf_hash"`
}

type sealFile struct {
	Seal         sealJSON      `json:"seal"`
	Attempts     []log.Attempt `json:"attempts"`
	LogPublicKey string        `json:"log_public_key"`
}
