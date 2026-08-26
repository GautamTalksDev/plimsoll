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

// Command plimsoll-static turns a SQLite transparency log into a static tree
// suitable for Cloudflare Pages (or any static host).
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	ilog "github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/staticlog"
)

func main() {
	dbPath := flag.String("db", "log.sqlite", "SQLite log path")
	outDir := flag.String("out", "./public", "output directory for the static tree")
	keyPath := flag.String("key", "", "Ed25519 log signing key (raw private/public bytes or JSON with public_key)")
	baseURL := flag.String("base-url", "https://plimsoll.gautamkhosla.com", "public base URL for badges and links")
	specPath := flag.String("spec", "SPEC-PREREG.md", "path to SPEC-PREREG.md")
	wasmPath := flag.String("wasm", "", "optional path to plimsoll_verify.wasm")
	flag.Parse()

	if *keyPath == "" {
		fmt.Fprintln(os.Stderr, "plimsoll-static: -key is required")
		os.Exit(2)
	}
	pub, err := loadPublicKey(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plimsoll-static: key: %v\n", err)
		os.Exit(1)
	}
	l, err := ilog.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plimsoll-static: open log: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = l.Close() }()

	spec := *specPath
	if abs, err := filepath.Abs(spec); err == nil {
		spec = abs
	}
	cfg := staticlog.Config{
		Log: l, OutDir: *outDir, PublicKey: pub,
		BaseURL: *baseURL, SpecPath: spec, WASMPath: *wasmPath,
	}
	if err := staticlog.Generate(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "plimsoll-static: %v\n", err)
		os.Exit(1)
	}
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304 -- operator-supplied key path
	if err != nil {
		return nil, err
	}
	if len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(append([]byte(nil), b...)), nil
	}
	if len(b) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(b).Public().(ed25519.PublicKey), nil
	}
	if block, _ := pem.Decode(b); block != nil {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PEM public key: %w", err)
		}
		ed, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("PEM is not an Ed25519 public key")
		}
		return ed, nil
	}
	var doc struct {
		PublicKey  string `json:"public_key"`
		PrivateKey string `json:"private_key"`
		Public     string `json:"public"`
		Private    string `json:"private"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("unrecognized key file (want 32/64 raw bytes, PEM, or JSON): %w", err)
	}
	for _, s := range []string{doc.PublicKey, doc.Public} {
		if s == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("decode public_key: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("public_key: want %d bytes, got %d", ed25519.PublicKeySize, len(raw))
		}
		return ed25519.PublicKey(raw), nil
	}
	for _, s := range []string{doc.PrivateKey, doc.Private} {
		if s == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("decode private_key: %w", err)
		}
		if len(raw) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("private_key: want %d bytes, got %d", ed25519.PrivateKeySize, len(raw))
		}
		return ed25519.PrivateKey(raw).Public().(ed25519.PublicKey), nil
	}
	return nil, fmt.Errorf("JSON key file missing public_key / private_key")
}
