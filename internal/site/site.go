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
	return strings.ReplaceAll(hash, ":", "%3A")
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

func renderMarkdownSafe(md string) template.HTML {
	var b strings.Builder
	for _, line := range strings.Split(md, "\n") {
		esc := template.HTMLEscapeString(line)
		switch {
		case strings.HasPrefix(line, "### "):
			b.WriteString("<h3>" + esc[4:] + "</h3>")
		case strings.HasPrefix(line, "## "):
			b.WriteString("<h2>" + esc[3:] + "</h2>")
		case strings.HasPrefix(line, "# "):
			b.WriteString("<h1>" + esc[2:] + "</h1>")
		case strings.HasPrefix(line, "- "):
			b.WriteString("<li>" + esc[2:] + "</li>")
		default:
			if strings.TrimSpace(line) == "" {
				continue
			}
			b.WriteString("<p>" + esc + "</p>")
		}
	}
	return template.HTML(b.String()) //nolint:gosec // G203 -- every line is HTML-escaped before tags are added
}

const pageT = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} · PLIMSOLL</title>
<link rel="stylesheet" href="/site.css">
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
<code>VERIFIED WITH DISCLOSURES</code> — a pass that carries context, not a failure.</p>
</div>
<h2>What it never sees</h2>
<p>Datasets, models, prompts and outputs never leave your machine. Only digests, metadata and
verdicts cross the boundary. There is no override on a sealed decision rule — not by flag,
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
{{if .Supersedes}}<p>Supersedes <code>{{.Supersedes}}</code>{{if .SupersedeReason}} — {{.SupersedeReason}}{{end}}</p>{{end}}
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
signature offline, and detect a rewritten history — no trust in this operator required.
Verification works against any conforming log, not only this one.</p>
<p>Specification CC0 · implementation Apache-2.0 ·
<a href="https://github.com/GautamTalksDev/plimsoll">source</a></p>
</footer>
</body></html>`
