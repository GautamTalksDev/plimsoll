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

package evidence_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestComplianceMappingWording(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "COMPLIANCE-MAPPING.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(b))
	for _, forbidden := range []string{"compliant", "certified", "audit-ready"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("forbidden word %q in COMPLIANCE-MAPPING.md", forbidden)
		}
	}
	if !strings.Contains(text, "designed to support documentation of") {
		t.Fatal("missing required framing language")
	}
}
