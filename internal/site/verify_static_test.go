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

package site_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GautamTalksDev/plimsoll/internal/site"
)

func TestVerifyPageEmbedded(t *testing.T) {
	mux := http.NewServeMux()
	site.MountVerify(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, path := range []string{"/verify", "/verify/", "/verify/index.html", "/verify/verify.js", "/verify/wasm_exec.js"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK && !(path == "/verify" && resp.StatusCode == http.StatusFound) {
			t.Fatalf("%s status=%d", path, resp.StatusCode)
		}
		if path == "/verify/index.html" || path == "/verify/" {
			html := string(body)
			if !strings.Contains(html, "never leaves this browser") {
				t.Fatal("missing privacy notice")
			}
			if strings.Contains(html, "google") || strings.Contains(html, "cdn") {
				t.Fatal("third-party reference in HTML")
			}
		}
	}
}
