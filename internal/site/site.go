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

// Package site renders the public PLIMSOLL static pages with strict escaping.
package site

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"os"
	"strings"

	"github.com/GautamTalksDev/plimsoll/internal/canonical"
	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
	"github.com/GautamTalksDev/plimsoll/internal/verify"
)

var errSealNotFound = errors.New("site: seal not found")

// Renderer serves HTML pages alongside the log API.
type Renderer struct {
	Log       *log.Log
	PublicKey ed25519.PublicKey
	SpecPath  string
	BaseURL   string
	templates *template.Template
}

// New creates a site renderer. specPath points at SPEC-PREREG.md.
func New(l *log.Log, pub ed25519.PublicKey, specPath, baseURL string) (*Renderer, error) {
	base := strings.TrimRight(baseURL, "/")
	t, err := template.New("site").Funcs(template.FuncMap{
		"sealPath": SealPath,
		"verifyURL": func(logURL, digest string) string {
			return verify.VerifyURL(VerifyBaseURL(base), logURL, digest)
		},
	}).Parse(pageT)
	if err != nil {
		return nil, err
	}
	return &Renderer{
		Log: l, PublicKey: pub, SpecPath: specPath,
		BaseURL: base, templates: t,
	}, nil
}

// Mount registers HTML page routes.
func (r *Renderer) Mount(mux *http.ServeMux, l *log.Log, pub ed25519.PublicKey) {
	r.Log = l
	r.PublicKey = pub
	mux.HandleFunc("/", r.handleHome)
	mux.HandleFunc("/seals", r.handleSeals)
	mux.HandleFunc("/key", r.handleKey)
	mux.HandleFunc("/spec", r.handleSpec)
	mux.HandleFunc("/run-your-own", r.handleRunYourOwn)
	MountVerify(mux)
}

// SealDir returns the filesystem- and URL-safe directory name for a seal digest.
// ':' is percent-encoded so the name is valid on Windows and in static URLs.
func SealDir(hash string) string {
	return strings.ReplaceAll(hash, ":", "-")
}

// ParseSealDir accepts either the current directory form (sha256-<hex>) or the
// canonical digest form (sha256:<hex>) and returns the canonical digest.
//
// The directory form must contain no percent-encoding. A static host decodes
// the request path once before matching a file, so a directory literally named
// "sha256%3A<hex>" is unreachable: the client asks for "sha256:<hex>", the
// lookup misses, and the host serves its HTML fallback with HTTP 200 rather
// than a 404. Clients then hang parsing HTML as JSON instead of failing.
func ParseSealDir(seg string) string {
	if strings.HasPrefix(seg, "sha256-") {
		return "sha256:" + strings.TrimPrefix(seg, "sha256-")
	}
	return seg
}

// SealPath returns the URL path for a seal digest ('/' + seal/{urlsafe_hash}).
func SealPath(hash string) string {
	return "/seal/" + SealDir(hash)
}

// ServeSeal renders per-seal history HTML.
func (r *Renderer) ServeSeal(w http.ResponseWriter, req *http.Request, sealHash string) {
	data, err := r.SealPage(sealHash)
	if err != nil {
		if errors.Is(err, errSealNotFound) {
			http.NotFound(w, req)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	r.render(w, data)
}

func (r *Renderer) handleHome(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}
	r.render(w, r.HomePage())
}

func (r *Renderer) handleSeals(w http.ResponseWriter, _ *http.Request) {
	data, err := r.SealsPage()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	r.render(w, data)
}

func (r *Renderer) handleKey(w http.ResponseWriter, _ *http.Request) {
	r.render(w, r.KeyPage())
}

func (r *Renderer) handleSpec(w http.ResponseWriter, _ *http.Request) {
	data, err := r.SpecPage()
	if err != nil {
		http.Error(w, "spec unavailable", http.StatusInternalServerError)
		return
	}
	r.render(w, data)
}

func (r *Renderer) handleRunYourOwn(w http.ResponseWriter, _ *http.Request) {
	r.render(w, r.RunPage())
}

func (r *Renderer) render(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=120")
	b, err := r.Render(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(b)
}

// Render executes the site template. html/template escapes user-supplied strings.
func (r *Renderer) Render(data map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	if err := r.templates.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// HomePage is the landing page data.
func (r *Renderer) HomePage() map[string]any {
	return map[string]any{"Page": "home", "Title": "PLIMSOLL"}
}

// SealsPage lists every seal, newest first.
func (r *Renderer) SealsPage() (map[string]any, error) {
	list, err := r.Log.AllSealSummaries()
	if err != nil {
		return nil, err
	}
	return map[string]any{"Page": "seals", "Title": "Recent seals", "Seals": list}, nil
}

// KeyPage is the HTML public-key page used by logd. Static hosting serves PEM at /key.
func (r *Renderer) KeyPage() map[string]any {
	return map[string]any{
		"Page": "key", "Title": "Log public key",
		"PublicKey": base64.StdEncoding.EncodeToString(r.PublicKey),
	}
}

// SpecPage renders SPEC-PREREG.md with every line HTML-escaped.
func (r *Renderer) SpecPage() (map[string]any, error) {
	b, err := os.ReadFile(r.SpecPath)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"Page": "spec", "Title": "Specification",
		"SpecHTML": renderMarkdownSafe(string(b)),
	}, nil
}

// RunPage is the self-hosted logd instructions page.
func (r *Renderer) RunPage() map[string]any {
	return map[string]any{"Page": "run", "Title": "Run your own log"}
}

type sealAttemptRow struct {
	No        int
	Verdict   string
	Digest    string
	VerifyURL string
}

// SealPage returns template data for one seal. Names and supersede reasons are
// plain strings; html/template escapes them on render.
func (r *Renderer) SealPage(sealHash string) (map[string]any, error) {
	rec, ok, err := r.Log.SealByHash(sealHash)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errSealNotFound
	}
	attempts, err := r.Log.AttemptsForSeal(sealHash)
	if err != nil {
		return nil, err
	}
	name := rec.SubmitterID
	supReason := ""
	var s seal.Seal
	if err := canonical.DecodeCanonical(rec.Canonical, &s); err == nil {
		if s.Subject.Name != "" {
			name = s.Subject.Name
		}
		if s.Supersedes != nil {
			supReason = s.Supersedes.Reason
		}
	}
	var rows []sealAttemptRow
	vbase := VerifyBaseURL(r.BaseURL)
	for _, a := range attempts {
		rows = append(rows, sealAttemptRow{
			a.AttemptNo, strings.ToUpper(a.Verdict), a.ResultDigest,
			verify.VerifyURL(vbase, r.BaseURL, a.ResultDigest),
		})
	}
	return map[string]any{
		"Page": "seal", "Title": name, "SealHash": sealHash, "SubjectName": name,
		"Supersedes": rec.Supersedes, "SupersedeReason": supReason, "Attempts": rows,
		"BadgeURL":  r.BaseURL + SealPath(sealHash) + "/badge.svg",
		"VerifyURL": verify.VerifyURL(vbase, r.BaseURL, ""),
		"LogURL":    r.BaseURL,
	}, nil
}

// renderMarkdownSafe converts a small, fixed subset of Markdown to HTML.
//
// Every line is HTML-escaped BEFORE any tag is added, and inline formatting is
// applied only to already-escaped text, so no input can introduce markup. It
// is deliberately not a general Markdown implementation: a full parser is a
// large dependency and a large attack surface for the single job of rendering
// one CC0 specification file.
func renderMarkdownSafe(md string) template.HTML {
	var b strings.Builder
	inCode := false
	inList := false
	inTable := false

	closeList := func() {
		if inList {
			b.WriteString("</ul>")
			inList = false
		}
	}
	closeTable := func() {
		if inTable {
			b.WriteString("</tbody></table>")
			inTable = false
		}
	}

	for _, line := range strings.Split(md, "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "```") {
			closeList()
			closeTable()
			if inCode {
				b.WriteString("</code></pre>")
			} else {
				b.WriteString("<pre><code>")
			}
			inCode = !inCode
			continue
		}
		if inCode {
			b.WriteString(template.HTMLEscapeString(line) + "\n")
			continue
		}

		esc := template.HTMLEscapeString(line)

		// A table separator row (|---|---|) opens the body; it prints nothing.
		if isTableSeparator(trimmed) && inTable {
			continue
		}
		if strings.HasPrefix(trimmed, "|") && strings.HasSuffix(trimmed, "|") {
			closeList()
			cells := splitTableRow(trimmed)
			if !inTable {
				b.WriteString("<table><thead><tr>")
				for _, c := range cells {
					b.WriteString("<th>" + inlineMarkdown(template.HTMLEscapeString(c)) + "</th>")
				}
				b.WriteString("</tr></thead><tbody>")
				inTable = true
				continue
			}
			b.WriteString("<tr>")
			for _, c := range cells {
				b.WriteString("<td>" + inlineMarkdown(template.HTMLEscapeString(c)) + "</td>")
			}
			b.WriteString("</tr>")
			continue
		}
		closeTable()

		switch {
		case strings.HasPrefix(line, "#### "):
			closeList()
			b.WriteString("<h4>" + inlineMarkdown(esc[5:]) + "</h4>")
		case strings.HasPrefix(line, "### "):
			closeList()
			b.WriteString("<h3>" + inlineMarkdown(esc[4:]) + "</h3>")
		case strings.HasPrefix(line, "## "):
			closeList()
			b.WriteString("<h2>" + inlineMarkdown(esc[3:]) + "</h2>")
		case strings.HasPrefix(line, "# "):
			closeList()
			b.WriteString("<h1>" + inlineMarkdown(esc[2:]) + "</h1>")
		case trimmed == "---":
			closeList()
			b.WriteString("<hr>")
		case strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* "):
			if !inList {
				b.WriteString("<ul>")
				inList = true
			}
			item := strings.TrimSpace(esc)
			b.WriteString("<li>" + inlineMarkdown(item[2:]) + "</li>")
		default:
			if trimmed == "" {
				closeList()
				continue
			}
			closeList()
			b.WriteString("<p>" + inlineMarkdown(esc) + "</p>")
		}
	}
	if inCode {
		b.WriteString("</code></pre>")
	}
	closeList()
	closeTable()
	return template.HTML(b.String()) //nolint:gosec // G203 -- input is escaped before any tag is added
}

// inlineMarkdown applies bold and inline code to text that is ALREADY
// HTML-escaped. It must never be called on raw input.
func inlineMarkdown(escaped string) string {
	escaped = wrapPairs(escaped, "**", "<strong>", "</strong>")
	escaped = wrapPairs(escaped, "`", "<code>", "</code>")
	return escaped
}

// wrapPairs replaces matched pairs of a delimiter with open/close tags. An
// unmatched trailing delimiter is left as literal text.
func wrapPairs(s, delim, open, close string) string {
	var b strings.Builder
	rest := s
	for {
		i := strings.Index(rest, delim)
		if i < 0 {
			b.WriteString(rest)
			return b.String()
		}
		j := strings.Index(rest[i+len(delim):], delim)
		if j < 0 {
			b.WriteString(rest)
			return b.String()
		}
		b.WriteString(rest[:i])
		b.WriteString(open)
		b.WriteString(rest[i+len(delim) : i+len(delim)+j])
		b.WriteString(close)
		rest = rest[i+len(delim)+j+len(delim):]
	}
}

func isTableSeparator(line string) bool {
	if !strings.HasPrefix(line, "|") {
		return false
	}
	for _, r := range line {
		if r != '|' && r != '-' && r != ':' && r != ' ' {
			return false
		}
	}
	return strings.Contains(line, "-")
}

func splitTableRow(line string) []string {
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

const pageT = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} · PLIMSOLL</title>
<link rel="stylesheet" href="/site.css">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
</head><body>
<nav><a href="/">Problem</a><a href="/seals">Seals</a><a href="/verify/">Verify</a><a href="/spec">Spec</a><a href="/key">Public key</a><a href="/run-your-own">Run your own</a></nav>
{{if eq .Page "home"}}
<h1>How many times did they run it?</h1>
<p class="lede">Someone tells you their model scores 0.87, up from 0.81. Every number is real.
The claim can still be worthless.</p>
<p>Moving a threshold after seeing the result is the obvious version, and everybody watches for it.
The version that actually happens is quieter: run the eval nine times across seeds, temperatures and
retrieval settings, publish the run that cleared the bar, and say nothing about the other eight.
Nothing was falsified. Nothing is checkable.</p>
<p>Git commits do not catch this. Signed results do not catch this. A vendor's own eval platform
structurally cannot, because the record of discarded attempts would be held by the party the
absence benefits.</p>
<h2>What this is</h2>
<p>Before you run, you publish a <strong>seal</strong>: your metric, threshold, decision rule and dataset
digest, appended to a public Merkle log. After you run, an <strong>attestation</strong> binds your results
to that seal. <strong>The log assigns the attempt number, not the client.</strong> A seal with five
attestations shows five attempts, with all five verdicts, permanently.</p>
<div class="callout">
<p>Iterating is normal. Hiding iteration is the problem. Multiple attempts verify as
<code>VERIFIED WITH DISCLOSURES</code>: a pass that carries context, not a failure.</p>
</div>
<h2>What it never sees</h2>
<p>Datasets, models, prompts and outputs never leave your machine. Only digests, metadata and
verdicts cross the boundary. There is no override on a sealed decision rule, not by flag,
config, or paid tier. Amendment is impossible; supersession with a public reason is mandatory.</p>
<p><a href="/verify/">Verify an attestation</a> in your browser, or read the
<a href="/spec">specification</a>.</p>
{{else if eq .Page "seals"}}
<h1>Recent seals</h1>
<table><tr><th>Subject</th><th>Seal hash</th><th>Attempts</th><th>Latest</th></tr>
{{range .Seals}}<tr>
<td><a href="{{sealPath .SealHash}}">{{.SubjectName}}</a></td>
<td><code>{{.SealHash}}</code></td><td>{{.AttemptCount}}</td><td>{{.LatestVerdict}}</td>
</tr>{{end}}</table>
{{else if eq .Page "seal"}}
<h1>{{.SubjectName}}</h1>
<p><a href="{{.VerifyURL}}">Verify this seal</a> · <a href="{{.VerifyURL}}"><img src="{{.BadgeURL}}" alt="plimsoll badge"></a></p>
<p><code>{{.SealHash}}</code></p>
{{if .Supersedes}}<p>Supersedes <code>{{.Supersedes}}</code>{{if .SupersedeReason}}, {{.SupersedeReason}}{{end}}</p>{{end}}
<h2>Attempts</h2>
<table><tr><th>#</th><th>Verdict</th><th>Digest</th><th></th></tr>
{{range .Attempts}}<tr><td>{{.No}}</td><td>{{.Verdict}}</td><td><code>{{.Digest}}</code></td><td><a href="{{.VerifyURL}}">Verify this</a></td></tr>
{{else}}<tr><td colspan="3">No attestations yet.</td></tr>{{end}}</table>
{{else if eq .Page "key"}}
<h1>Log public key</h1>
<pre><code>{{.PublicKey}}</code></pre>
{{else if eq .Page "spec"}}
<h1>Pre-registration specification</h1>
<div>{{.SpecHTML}}</div>
{{else if eq .Page "run"}}
<h1>Run your own log</h1>
<p>Anyone can run <code>plimsolld</code>. Verification uses <code>plimsoll verify --log &lt;url&gt;</code>, not our database.</p>
<pre><code>plimsolld -addr :8080 -db ./log.sqlite -key ./log-signing.key</code></pre>
{{end}}
<footer>
<p>The log is a public git repository. Anyone can clone it, replay every Merkle leaf and
signature offline, and detect a rewritten history, with no trust in this operator required.
Verification works against any conforming log, not only this one.</p>
<p>Publishing to this log is permanent. Entries cannot be edited or deleted.
Read the privacy notice before you publish.</p>
<p>Specification CC0 · implementation Apache-2.0 ·
<a href="https://github.com/GautamTalksDev/plimsoll">Source</a> ·
<a href="https://github.com/GautamTalksDev/plimsoll/blob/main/PRIVACY.md">Privacy</a> ·
<a href="https://github.com/GautamTalksDev/plimsoll/blob/main/TERMS.md">Terms</a> ·
<a href="https://github.com/GautamTalksDev/plimsoll/blob/main/SECURITY.md">Security</a></p>
</footer>
</body></html>`
