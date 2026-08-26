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

package decide

// Term is one auditable step in evaluating the sealed expression.
type Term struct {
	Label      string `json:"label"`
	Identifier string `json:"identifier,omitempty"`
	Value      string `json:"value,omitempty"`
	Comparator string `json:"comparator,omitempty"`
	Literal    string `json:"literal,omitempty"`
	Outcome    bool   `json:"outcome"`
}

// Verdict is the outcome of applying a sealed decision rule to a ResultSet.
type Verdict struct {
	Result     string   `json:"result"` // PASS | FAIL | INVALID
	Expression string   `json:"expression"`
	Terms      []Term   `json:"terms"`
	Reasons    []string `json:"reasons,omitempty"`
}

// ExitCode maps verdict results to process exit codes. INVALID is distinct
// from FAIL: it signals a pre-registration mismatch, not a failed SUT.
func (v *Verdict) ExitCode() int {
	if v == nil {
		return 2
	}
	switch v.Result {
	case "PASS":
		return 0
	case "FAIL":
		return 1
	default:
		return 2
	}
}
