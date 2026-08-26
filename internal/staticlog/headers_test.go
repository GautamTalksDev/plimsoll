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

package staticlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The site renders attacker-supplied seal names. If these headers are ever
// dropped from the generated tree, CSP stops protecting the verify page.
func TestWriteHeadersIncludesSecurityHeaders(t *testing.T) {
	dir := t.TempDir()
	if err := writeHeaders(dir); err != nil {
		t.Fatalf("writeHeaders: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "_headers"))
	if err != nil {
		t.Fatalf("read _headers: %v", err)
	}
	got := string(b)

	for _, want := range []string{
		"/*",
		"Content-Security-Policy:",
		"default-src 'none'",
		"script-src 'self' 'wasm-unsafe-eval'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
		"X-Content-Type-Options: nosniff",
		"X-Frame-Options: DENY",
		"Referrer-Policy: no-referrer",
		"Strict-Transport-Security:",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("_headers missing %q", want)
		}
	}

	// CSP must not permit inline or remote script execution.
	for _, bad := range []string{"'unsafe-inline'", "'unsafe-eval'", "http://"} {
		if strings.Contains(got, bad) {
			t.Errorf("_headers must not contain %q", bad)
		}
	}

	// Cache rules must survive alongside the security headers.
	if !strings.Contains(got, "/checkpoint\n  Cache-Control: public, max-age=60") {
		t.Error("_headers lost the /checkpoint cache rule")
	}
}
