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

package badge

import (
	"strings"
	"testing"

	"github.com/GautamTalksDev/plimsoll/internal/log"
)

func TestBadgeSemantics(t *testing.T) {
	grey := StyleForAttempts(nil)
	if !strings.Contains(grey.RightLabel, "sealed") {
		t.Fatal(grey)
	}
	green := StyleForAttempts([]log.Attempt{{Verdict: "pass"}})
	if green.RightLabel != "plimsoll: verified" {
		t.Fatal(green)
	}
	blue := StyleForAttempts([]log.Attempt{
		{Verdict: "fail", AttemptNo: 1},
		{Verdict: "fail", AttemptNo: 2},
		{Verdict: "pass", AttemptNo: 3},
	})
	if blue.RightLabel != "plimsoll: verified (3)" {
		t.Fatal(blue)
	}
	red := StyleForAttempts([]log.Attempt{{Verdict: "fail"}})
	if red.RightLabel != "plimsoll: failed" {
		t.Fatal(red)
	}
}

func TestBadgeEscapesXSS(t *testing.T) {
	s := Style{LeftColor: "#555", RightColor: "#4c1", RightLabel: `<script>alert(1)</script>`}
	out := string(SVG(s))
	if strings.Contains(out, "<script>") {
		t.Fatalf("unescaped script in SVG: %s", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("expected escaped script: %s", out)
	}
}
