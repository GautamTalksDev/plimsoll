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

package cliout

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
)

// Printer renders human or JSON CLI output safely.
type Printer struct {
	Out   io.Writer
	Err   io.Writer
	JSON  bool
	IsTTY bool
}

func New() *Printer {
	return &Printer{
		Out:   os.Stdout,
		Err:   os.Stderr,
		IsTTY: isTerminal(os.Stdout),
	}
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// Sanitize removes terminal control sequences and unsafe bidi from untrusted text.
func Sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\n' || r == '\t' || r == '\r' {
			b.WriteRune(r)
			continue
		}
		if unicode.IsControl(r) {
			continue
		}
		if r == '\u202e' || r == '\u202d' || r == '\u200f' || r == '\u200e' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (p *Printer) Printf(format string, args ...any) {
	_, _ = fmt.Fprint(p.Out, Sanitize(fmt.Sprintf(format, args...)))
}

func (p *Printer) Println(s string) {
	_, _ = fmt.Fprintln(p.Out, Sanitize(s))
}

func (p *Printer) Warn(s string) {
	if p.JSON {
		return
	}
	msg := Sanitize(s)
	if p.IsTTY {
		_, _ = fmt.Fprintf(p.Err, "\x1b[33m%s\x1b[0m\n", msg)
		return
	}
	_, _ = fmt.Fprintln(p.Err, msg)
}

func (p *Printer) Success(s string) {
	if p.JSON {
		return
	}
	msg := Sanitize(s)
	if p.IsTTY {
		_, _ = fmt.Fprintf(p.Out, "\x1b[32m%s\x1b[0m\n", msg)
	} else {
		_, _ = fmt.Fprintln(p.Out, msg)
	}
}

func (p *Printer) EmitJSON(v any) error {
	enc := json.NewEncoder(p.Out)
	enc.SetEscapeHTML(true)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

const LocalOnlyWarning = "LOCAL ONLY - this seal is not independently timestamped and proves nothing to a third party. Re-run with --publish."

// SubmittedPending is printed after HTTP 202 (async append). Never implies the entry is logged yet.
const SubmittedPending = `Submitted. The log appends within about a minute.
Run: plimsoll verify <file> --log <url>   to confirm inclusion.`

func (p *Printer) PrintLocalOnlyWarning() {
	if p.JSON {
		return
	}
	p.Warn(LocalOnlyWarning)
}

func (p *Printer) PrintSubmittedPending(verifyFile, logURL string) {
	if p.JSON {
		return
	}
	msg := SubmittedPending
	if verifyFile != "" && logURL != "" {
		msg = fmt.Sprintf("Submitted. The log appends within about a minute.\nRun: plimsoll verify %s --log %s   to confirm inclusion.",
			verifyFile, logURL)
	}
	p.Println(msg)
}

func (p *Printer) PrintAttemptLine(attemptNo int, previous []string) {
	if p.JSON {
		return
	}
	prev := "none"
	if len(previous) > 0 {
		parts := make([]string, len(previous))
		for i, v := range previous {
			parts[i] = Sanitize(v)
		}
		prev = strings.Join(parts, ", ")
	}
	p.Printf("Attempt %d of this seal. Previous attempts: %s.\n", attemptNo, prev)
}
