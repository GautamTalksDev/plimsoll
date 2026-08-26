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

package site

import (
	"strings"
	"testing"
)

const testHash = "sha256:" + "ab12" + "34567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"

// A static host decodes the request path once before matching a file, so any
// percent-encoding in a generated directory name makes that file unreachable
// and the host answers with its HTML fallback under HTTP 200. Clients then
// hang parsing HTML as JSON. Generated paths must contain no '%'.
func TestSealPathHasNoPercentEncoding(t *testing.T) {
	for _, got := range []string{SealDir(testHash), SealPath(testHash)} {
		if strings.Contains(got, "%") {
			t.Errorf("generated path contains percent-encoding: %q", got)
		}
		if strings.Contains(got, ":") {
			t.Errorf("generated path contains a colon: %q", got)
		}
	}
}

func TestParseSealDirRoundTrips(t *testing.T) {
	if got := ParseSealDir(SealDir(testHash)); got != testHash {
		t.Errorf("round trip: got %q want %q", got, testHash)
	}
	// The canonical digest form must pass through unchanged, because a real
	// HTTP server has already decoded %3A to ':' before we see it.
	if got := ParseSealDir(testHash); got != testHash {
		t.Errorf("canonical form: got %q want %q", got, testHash)
	}
}
