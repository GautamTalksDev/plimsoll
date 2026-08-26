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

package log

import "errors"

var (
	errEmptyTree   = errors.New("log: empty tree")
	errBadIndex    = errors.New("log: leaf index out of range")
	errBadTreeSize = errors.New("log: invalid tree size")
)

// InclusionProof is a Merkle inclusion proof for one leaf index.
type InclusionProof struct {
	Index     int64
	TreeSize  int64
	LeafHash  []byte
	AuditPath [][]byte
	RootHash  []byte
}

// ConsistencyProof is a Merkle consistency proof between two tree sizes.
type ConsistencyProof struct {
	OldSize   int64
	NewSize   int64
	OldRoot   []byte
	NewRoot   []byte
	AuditPath [][]byte
}

// Entry is one leaf in the append-only Merkle log.
type Entry struct {
	Index        int64  `json:"index"`
	Kind         string `json:"kind"`
	SealHash     string `json:"seal_hash,omitempty"`
	AttemptNo    int    `json:"attempt_no,omitempty"`
	ResultDigest string `json:"result_digest,omitempty"`
	Verdict      string `json:"verdict,omitempty"`
	CanonicalB64 string `json:"canonical_b64"`
	LeafHash     string `json:"leaf_hash"`
	SubmittedAt  int64  `json:"submitted_at"`
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
