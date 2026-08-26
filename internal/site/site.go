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
	"html/template"
	"net/http"
	"os"
	"strings"

	"github.com/GautamTalksDev/plimsoll/internal/canonical"
	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
	"github.com/GautamTalksDev/plimsoll/internal/verify"
)

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
		"sealPath": func(hash string) string {
			return "/seal/" + strings.ReplaceAll(hash, ":", "%3A")
		},
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

// ServeSeal renders per-seal history HTML.
func (r *Renderer) ServeSeal(w http.ResponseWriter, req *http.Request, sealHash string) {
	rec, ok, err := r.Log.SealByHash(sealHash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, req)
		return
	}
	attempts, err := r.Log.AttemptsForSeal(sealHash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
	type row struct {
		No        int
		Verdict   string
		Digest    string
		VerifyURL string
	}
	var rows []row
	vbase := VerifyBaseURL(r.BaseURL)
	for _, a := range attempts {
		rows = append(rows, row{
			a.AttemptNo, strings.ToUpper(a.Verdict), a.ResultDigest,
			verify.VerifyURL(vbase, r.BaseURL, a.ResultDigest),
		})
	}
	r.render(w, map[string]any{
		"Page": "seal", "Title": name, "SealHash": sealHash, "SubjectName": name,
		"Supersedes": rec.Supersedes, "SupersedeReason": supReason, "Attempts": rows,
		"BadgeURL":  r.BaseURL + "/seal/" + strings.ReplaceAll(sealHash, ":", "%3A") + "/badge.svg",
		"VerifyURL": verify.VerifyURL(vbase, r.BaseURL, ""),
		"LogURL":    r.BaseURL,
	})
}

func (r *Renderer) handleHome(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}
	r.render(w, map[string]any{"Page": "home", "Title": "PLIMSOLL"})
}

func (r *Renderer) handleSeals(w http.ResponseWriter, _ *http.Request) {
	list, err := r.Log.RecentSeals(100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	r.render(w, map[string]any{"Page": "seals", "Title": "Recent seals", "Seals": list})
}

func (r *Renderer) handleKey(w http.ResponseWriter, _ *http.Request) {
	r.render(w, map[string]any{
		"Page": "key", "Title": "Log public key",
		"PublicKey": base64.StdEncoding.EncodeToString(r.PublicKey),
	})
}

func (r *Renderer) handleSpec(w http.ResponseWriter, _ *http.Request) {
	b, err := os.ReadFile(r.SpecPath)
	if err != nil {
		http.Error(w, "spec unavailable", http.StatusInternalServerError)
		return
	}
	r.render(w, map[string]any{
		"Page": "spec", "Title": "Specification",
		"SpecHTML": renderMarkdownSafe(string(b)),
	})
}

func (r *Renderer) handleRunYourOwn(w http.ResponseWriter, _ *http.Request) {
	r.render(w, map[string]any{"Page": "run", "Title": "Run your own log"})
}

func (r *Renderer) render(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=120")
	var buf bytes.Buffer
	if err := r.templates.Execute(&buf, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(buf.Bytes())
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
<style>
body{font-family:system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#111}
nav a{margin-right:1rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:.4rem}
code,pre{background:#f4f4f4;padding:.2rem .4rem;border-radius:3px;word-break:break-all}
</style></head><body>
<nav><a href="/">Problem</a><a href="/seals">Seals</a><a href="/verify/">Verify</a><a href="/spec">Spec</a><a href="/key">Public key</a><a href="/run-your-own">Run your own</a></nav>
{{if eq .Page "home"}}
<h1>Verify evaluations you ran with your own tools</h1>
<p>PLIMSOLL is an integrity layer for ML evaluation claims. You pre-register a decision rule and dataset digest,
run your own harness locally, then publish a signed seal and attestation to a transparency log anyone can verify.</p>
<p>We never receive your dataset, prompts, or model outputs — only digests, signatures, and aggregate verdicts.</p>
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
</body></html>`
