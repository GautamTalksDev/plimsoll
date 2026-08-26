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
	"encoding/json"
	"strings"
	"testing"
)

// An empty audit path must serialize as [] and never as null. Published
// proofs are parsed by third-party verifiers; null is a different shape.
func TestConsistencyFileEmptyAuditPathIsArray(t *testing.T) {
	b, err := json.Marshal(consistencyFile{AuditPath: make([]string, 0)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)
	if !strings.Contains(got, `"audit_path":[]`) {
		t.Errorf("empty audit path did not marshal as []: %s", got)
	}
	if strings.Contains(got, `"audit_path":null`) {
		t.Errorf("audit path marshalled as null: %s", got)
	}
}
