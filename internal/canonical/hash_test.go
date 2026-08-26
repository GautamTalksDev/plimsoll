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

package canonical

import "testing"

func TestSum256Empty(t *testing.T) {
	t.Parallel()
	const want = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := Sum256(nil); got != want {
		t.Fatalf("Sum256(nil) = %q, want %q", got, want)
	}
}

func TestSum256KnownVector(t *testing.T) {
	t.Parallel()
	const want = "25318c2d6a847c6a4e9a7931ca516e5d93e3052420351235125b4f22bc9cb56e"
	if got := Sum256([]byte("plimsoll")); got != want {
		t.Fatalf("Sum256(%q) = %q, want %q", "plimsoll", got, want)
	}
}

func TestSum256Deterministic(t *testing.T) {
	t.Parallel()
	in := []byte("plimsoll")
	if a, b := Sum256(in), Sum256(in); a != b {
		t.Fatalf("Sum256 is not deterministic: %q vs %q", a, b)
	}
}
