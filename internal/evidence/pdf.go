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

package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	pdfVersion   = "1.4"
	linesPerPage = 55
	lineLeading  = 12
	pageWidth    = 612
	pageHeight   = 792
	leftMargin   = 50
	topY         = 750
)

// ToJSON returns deterministic indented JSON for a pack.
func ToJSON(p *Pack) ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// ToPDF renders a deterministic PDF for the same pack input.
func ToPDF(p *Pack) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("evidence: nil pack")
	}
	return buildPDF(packLines(p), p.GeneratedAt)
}

func packLines(p *Pack) []string {
	var out []string
	add := func(s string) { out = append(out, s) }
	add("PLIMSOLL Evidence Pack")
	add("Version: " + p.Version)
	add(fmt.Sprintf("Generated at (log timestamp): %d", p.GeneratedAt))
	add("Seal hash: " + p.SealHash)
	if p.LogURL != "" {
		add("Log URL: " + p.LogURL)
	}
	add("Log public key: " + p.LogPublicKey)
	add("Browser verifier: " + p.BrowserVerifierURL)
	if p.VerifyURL != "" {
		add("Verify this seal: " + p.VerifyURL)
	}
	add("")
	add("=== Pre-registration (YAML) ===")
	for _, line := range strings.Split(p.Preregistration.YAML, "\n") {
		add(line)
	}
	add("")
	add("=== Seal inclusion proof ===")
	add(fmt.Sprintf("Log index: %d  submitted_at: %d", p.SealInclusion.LogIndex, p.SealInclusion.SubmittedAt))
	add(fmt.Sprintf("Checkpoint tree_size: %d timestamp: %d", p.SealInclusion.Checkpoint.TreeSize, p.SealInclusion.Checkpoint.Timestamp))
	add("Root hash: " + p.SealInclusion.Checkpoint.RootHash)
	add("")
	for _, att := range p.Attempts {
		add(fmt.Sprintf("=== Attempt %d (%s) ===", att.AttemptNo, att.Verdict))
		if att.VerifyURL != "" {
			add("Verify this: " + att.VerifyURL)
		}
		add(fmt.Sprintf("submitted_at: %d  result_digest: %s", att.SubmittedAt, att.ResultDigest))
		add(fmt.Sprintf("Verification verdict: %s", att.Verification.Verdict))
		for _, c := range att.Verification.Checks {
			status := "FAIL"
			if c.Pass {
				status = "PASS"
			}
			add(fmt.Sprintf("  %s %s: %s", c.ID, status, c.Reason))
		}
		add(fmt.Sprintf("Inclusion index: %d checkpoint tree_size: %d", att.Inclusion.LogIndex, att.Inclusion.Checkpoint.TreeSize))
		add("")
	}
	if len(p.SupersedeChain) > 0 {
		add("=== Supersede chain (oldest first) ===")
		for _, link := range p.SupersedeChain {
			line := fmt.Sprintf("%s supersedes %s", link.SealHash, link.Supersedes)
			if link.SupersedeReason != "" {
				line += " reason: " + link.SupersedeReason
			}
			add(line)
		}
		add("")
	}
	add("=== Verification instructions ===")
	for i, step := range p.Instructions {
		add(fmt.Sprintf("%d. %s", i+1, step))
	}
	return out
}

func paginate(lines []string, perPage int) [][]string {
	if perPage <= 0 {
		perPage = linesPerPage
	}
	var pages [][]string
	for i := 0; i < len(lines); i += perPage {
		end := i + perPage
		if end > len(lines) {
			end = len(lines)
		}
		pages = append(pages, lines[i:end])
	}
	if len(pages) == 0 {
		pages = append(pages, []string{""})
	}
	return pages
}

func pageStreamFixed(lines []string) string {
	var cmds []string
	cmds = append(cmds, "BT", "/F1 10 Tf", fmt.Sprintf("1 0 0 1 %d %d Tm", leftMargin, topY))
	for i, line := range lines {
		if i > 0 {
			cmds = append(cmds, fmt.Sprintf("0 -%d Td", lineLeading))
		}
		cmds = append(cmds, fmt.Sprintf("(%s) Tj", pdfEscape(line)))
	}
	cmds = append(cmds, "ET")
	return strings.Join(cmds, "\n")
}

func pdfEscape(s string) string {
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\', '(', ')':
			out = append(out, '\\', c)
		default:
			if c < 32 || c > 126 {
				out = append(out, fmt.Sprintf("\\%03o", c)...)
			} else {
				out = append(out, c)
			}
		}
	}
	return string(out)
}

func joinPDF(parts []string) string {
	return strings.Join(parts, " ")
}

func buildPDF(lines []string, generatedAt int64) ([]byte, error) {
	pages := paginate(lines, linesPerPage)
	pagesObjNum := 2
	pageNums := make([]int, len(pages))
	contentNums := make([]int, len(pages))
	fontObjNum := 3 + len(pages)*2
	for i := range pages {
		pageNums[i] = 3 + i*2
		contentNums[i] = 4 + i*2
	}

	var buf bytes.Buffer
	offsets := make([]int, fontObjNum+1)
	writeObj := func(num int, body string) {
		offsets[num] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", num, body)
	}

	buf.WriteString("%PDF-")
	buf.WriteString(pdfVersion)
	buf.WriteByte('\n')
	writeObj(1, fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R >>", pagesObjNum))
	kids := make([]string, len(pageNums))
	for i, p := range pageNums {
		kids[i] = fmt.Sprintf("%d 0 R", p)
	}
	writeObj(pagesObjNum, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", joinPDF(kids), len(pages)))
	for i, chunk := range pages {
		stream := pageStreamFixed(chunk)
		writeObj(pageNums[i], fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %d %d] /Contents %d 0 R /Resources << /Font << /F1 %d 0 R >> >> >>",
			pagesObjNum, pageWidth, pageHeight, contentNums[i], fontObjNum))
		writeObj(contentNums[i], fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream))
	}
	writeObj(fontObjNum, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

	xrefStart := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", fontObjNum+1)
	fmt.Fprintf(&buf, "0000000000 65535 f \n")
	for i := 1; i <= fontObjNum; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	date := pdfDate(generatedAt)
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R /Info << /Producer (PLIMSOLL) /CreationDate (%s) /ModDate (%s) >> >>\nstartxref\n%d\n%%%%EOF\n",
		fontObjNum+1, date, date, xrefStart)
	return buf.Bytes(), nil
}

func pdfDate(unix int64) string {
	t := time.Unix(unix, 0).UTC()
	return fmt.Sprintf("D:%04d%02d%02d%02d%02d%02dZ",
		t.Year(), int(t.Month()), t.Day(), t.Hour(), t.Minute(), t.Second())
}
