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
