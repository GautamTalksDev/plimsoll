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

// Package badge renders shields-style SVG badges for seal status.
package badge

import (
	"fmt"
	"strings"

	"github.com/GautamTalksDev/plimsoll/internal/log"
)

// Style is badge color and right-hand label.
type Style struct {
	LeftColor  string
	RightColor string
	RightLabel string
}

// StyleForAttempts computes badge semantics from attempt history.
// Badge never hides attempt count on PASS.
func StyleForAttempts(attempts []log.Attempt) Style {
	left := Style{LeftColor: "#555", RightColor: "#9f9f9f", RightLabel: "sealed"}
	if len(attempts) == 0 {
		left.RightLabel = "plimsoll: sealed"
		return left
	}
	latest := attempts[len(attempts)-1]
	v := strings.ToLower(latest.Verdict)
	switch v {
	case "pass":
		if len(attempts) == 1 {
			return Style{LeftColor: "#555", RightColor: "#4c1", RightLabel: "plimsoll: verified"}
		}
		return Style{
			LeftColor:  "#555",
			RightColor: "#007ec6",
			RightLabel: fmt.Sprintf("plimsoll: verified (%d)", len(attempts)),
		}
	case "fail":
		return Style{LeftColor: "#555", RightColor: "#e05d44", RightLabel: "plimsoll: failed"}
	default:
		return Style{LeftColor: "#555", RightColor: "#fe7d37", RightLabel: "plimsoll: invalid"}
	}
}

// SVG renders a shields-style badge. Text is XML-escaped.
func SVG(style Style) []byte {
	leftText := "plimsoll"
	rightText := xmlEscape(style.RightLabel)
	leftW := textWidth(leftText) + 10
	rightW := textWidth(style.RightLabel) + 10
	totalW := leftW + rightW
	xRight := leftW
	return []byte(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s">
<title>%s</title>
<linearGradient id="s" x2="0" y2="100%%">
<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
<stop offset="1" stop-opacity=".1"/>
</linearGradient>
<clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)">
<rect width="%d" height="20" fill="%s"/>
<rect x="%d" width="%d" height="20" fill="%s"/>
<rect width="%d" height="20" fill="url(#s)"/>
</g>
<g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,sans-serif" font-size="11">
<text x="%d" y="14">%s</text>
<text x="%d" y="14">%s</text>
</g></svg>`,
		totalW, xmlEscape(style.RightLabel),
		xmlEscape(style.RightLabel),
		totalW,
		leftW, style.LeftColor,
		xRight, rightW, style.RightColor,
		totalW,
		leftW/2, xmlEscape(leftText),
		xRight+rightW/2, rightText,
	))
}

func textWidth(s string) int {
	return len(s)*6 + 4
}

func xmlEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
