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

// Package canonical is the trust-path canonicalizer. Every later verdict
// depends on these bytes. The package is pure: no I/O, no network, and it
// never transmits rows, datasets, models, prompts, or outputs.
package canonical

const (
	// CanonVersionPrefix is prepended to RFC 8785 JCS output.
	// Distinct from DatasetVersionPrefix; do not mix them.
	CanonVersionPrefix = "plimsoll-canon-v1\n"

	// DatasetVersionPrefix is prepended to a sorted multiset of
	// canonical rows. Distinct from CanonVersionPrefix.
	DatasetVersionPrefix = "plimsoll-dataset-v1\n"

	// MaxInputBytes is the exclusive upper bound on a single JSON
	// document passed to Canonicalize. Inputs larger than this are
	// rejected before parse.
	MaxInputBytes = 1 << 20
)
