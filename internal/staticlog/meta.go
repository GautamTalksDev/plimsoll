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

package staticlog

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"path/filepath"
)

func writeKey(outDir string, pub ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("staticlog: marshal public key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	b64 := base64.StdEncoding.EncodeToString(pub)
	body := append([]byte(nil), pemBytes...)
	body = append(body, []byte("# raw Ed25519 public key (base64)\n")...)
	body = append(body, []byte(b64)...)
	body = append(body, '\n')
	return writeBytes(filepath.Join(outDir, "key"), body)
}

func writeHeaders(outDir string) error {
	// Security headers apply to every path. The site serves attacker-supplied
	// seal names and reasons, so CSP is defence in depth behind escaping.
	// 'wasm-unsafe-eval' is required by the WASM verifier and nothing else.
	const headers = `/*
  Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: no-referrer
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Resource-Policy: same-origin
  Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=()
  Strict-Transport-Security: max-age=31536000; includeSubDomains
/checkpoint
  Cache-Control: public, max-age=60
/checkpoints/*
  Cache-Control: public, max-age=31536000, immutable
/entries/*
  Cache-Control: public, max-age=31536000, immutable
/proof/*
  Cache-Control: public, max-age=31536000, immutable
/seal/*
  Cache-Control: public, max-age=300
`
	return writeBytes(filepath.Join(outDir, "_headers"), []byte(headers))
}

func writeRedirects(outDir string) error {
	// Cloudflare Pages _redirects: only exact path rewrites. Query-string
	// logd URLs (/proof/inclusion?idx=, /entries?from=&to=) cannot be
	// remapped to arbitrary static files; clients should use the path form
	// (see docs/STATIC-LOG.md). logfetch tries path URLs first.
	const redirects = `/entries  /entries/index.json  200
/seals  /seals/index.html  200
/spec  /spec/index.html  200
/run-your-own  /run-your-own/index.html  200
/verify  /verify/  301
`
	return writeBytes(filepath.Join(outDir, "_redirects"), []byte(redirects))
}
