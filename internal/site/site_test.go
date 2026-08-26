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

package site

import (
	"bytes"
	"crypto/ed25519"
	"html/template"
	"strings"
	"testing"
)

func TestSubjectNameEscapesXSS(t *testing.T) {
	name := `<script>alert("xss")</script>`
	var buf bytes.Buffer
	err := template.Must(template.New("t").Parse(`<h1>{{.}}</h1>`)).Execute(&buf, name)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>") {
		t.Fatalf("unescaped: %s", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("expected escaped: %s", out)
	}
}

func TestRendererXSSInSealPage(t *testing.T) {
	r, err := New(nil, ed25519.PublicKey{}, "", "http://localhost")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	data := map[string]any{
		"Page": "seal", "Title": `<img onerror=alert(1)>`, "SubjectName": `<script>x</script>`,
		"SealHash": "sha256:abc", "BadgeURL": "/badge.svg", "Attempts": nil,
	}
	if err := r.templates.Execute(&buf, data); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "<script>") {
		t.Fatalf("xss leaked: %s", buf.String())
	}
}
