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

package decide

import "testing"

func TestReplayVerdict(t *testing.T) {
	terms := []Term{{
		Identifier: "acc.mean",
		Comparator: ">=",
		Literal:    "0.5",
		Value:      "0.9",
		Outcome:    true,
	}}
	got, err := ReplayVerdict("acc.mean >= 0.5", terms)
	if err != nil {
		t.Fatal(err)
	}
	if got != "PASS" {
		t.Fatalf("got %q", got)
	}
	terms[0].Outcome = false
	got, err = ReplayVerdict("acc.mean >= 0.5", terms)
	if err != nil {
		t.Fatal(err)
	}
	if got != "FAIL" {
		t.Fatalf("got %q", got)
	}
}
