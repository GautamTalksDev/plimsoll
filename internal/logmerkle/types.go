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

package logmerkle

// Attempt is one attested evaluation against a seal, in attempt order.
type Attempt struct {
	Idx          int64  `json:"index"`
	AttemptNo    int    `json:"attempt_no"`
	SealHash     string `json:"seal_hash"`
	ResultDigest string `json:"result_digest"`
	Verdict      string `json:"verdict"`
	SubmittedAt  int64  `json:"submitted_at"`
	LeafHash     string `json:"leaf_hash"`
}
