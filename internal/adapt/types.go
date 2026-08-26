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

package adapt

import "encoding/json"

// MetricValues holds per-row metric values in their original string form.
// Adapters map and extract only; they never compute aggregates.
type MetricValues struct {
	MetricID string
	Raw      []string // ORIGINAL string representations, in row order
	N        int
}

// ResultSet is the normalized harness output used by the decision engine.
type ResultSet struct {
	Harness    string
	HarnessVer string
	Metrics    map[string]MetricValues
	RowDigest  string // digest over per-row identifiers only
	Extra      json.RawMessage
}
