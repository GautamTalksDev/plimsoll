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
	"embed"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

//go:embed verify
var verifyFS embed.FS

// MountVerify serves the browser verifier at /verify/ (same-origin static assets).
func MountVerify(mux *http.ServeMux) {
	sub, err := fs.Sub(verifyFS, "verify")
	if err != nil {
		return
	}
	fileServer := http.FileServer(http.FS(sub))
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/verify" {
			http.Redirect(w, r, "/verify/", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})
	mux.Handle("/verify/", http.StripPrefix("/verify/", fileServer))
}

// VerifyBaseURL returns the browser verifier URL for this site.
func VerifyBaseURL(baseURL string) string {
	return strings.TrimRight(baseURL, "/") + "/verify"
}

// CopyVerify writes the embedded browser verifier assets into dstDir.
func CopyVerify(dstDir string) error {
	sub, err := fs.Sub(verifyFS, "verify")
	if err != nil {
		return err
	}
	return fs.WalkDir(sub, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(dstDir, path)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := fs.ReadFile(sub, path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644) //nolint:gosec // G306 -- public static assets
	})
}
